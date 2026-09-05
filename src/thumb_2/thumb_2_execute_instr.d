import std.format;
import std.conv      : to;
import std.typecons  : tuple, Tuple;
import std.array     : appender;
import std.traits    : Parameters, ReturnType;
import std.algorithm : canFind;

import scb_defs;
import cortex_m_core;
import memory_sections;
import vm;

import thumb_2_opcodes;
import thumb_2_opcode_defs;
import thumb_2_instrs;

// 16-bit instructions
import thumb_2_shift_add_sub_16;
import thumb_2_ldr_lit_16;
import thumb_2_data_proc_16;
import thumb_2_special_exchange_16;
import thumb_2_gen_pc_rel_addr_16;
import thumb_2_gen_sp_rel_addr_16;
import thumb_2_cond_branch_sup_call_16;
import thumb_2_uncond_branch_16;
import thumb_2_misc_16;
import thumb_2_store_mult_reg_16;
import thumb_2_load_store_single_data_item_16;
import thumb_2_load_mult_reg_16;
// 32-bit instructions
import thumb_2_load_store_dual_exc_32;
import thumb_2_branch_misc_ctrl_32;
import thumb_2_data_proc_bin_imm_32;
import thumb_2_data_proc_reg_32;
import thumb_2_data_proc_shift_reg_32;
import thumb_2_data_proc_mod_imm_32;
import thumb_2_load_byte_32;
import thumb_2_load_half_word_32;
import thumb_2_load_store_multiple_32;
import thumb_2_load_word_32;
import thumb_2_long_mult_acc_div_32;
import thumb_2_floating_point_ext_32;
import thumb_2_mult_mult_acc_32;
import thumb_2_store_single_data_item_32;
import thumb_2_misc_ops_32;
version (ARMv8_M) {
  import vm8_loop;
  import vm8_M_se;
  import helium;
}

__gshared opcode[] tested_opcodes;

void record_tested_opcode(opcode op) {
    if (!tested_opcodes.canFind(op))
        tested_opcodes ~= op;
}

void 
execute_instr
(vm_t,t)
(const t instr, ref vm_t vm) {

  vm.check_pc_modified(); // make sure pc_modified flag is cleared
  vm.last_instr.reset();

  bool handled = false;

  if (!vm.it_block_stack_empty()) {
    if (!vm.it_condition_is_met!(t)())
      return;
  }

  foreach (member; __traits(allMembers, opcode))
  {
      enum op = mixin("opcode." ~ member);

      if (instr.op == op)
      {
          static if (__traits(compiles, mixin("execute_" ~ member)))
          {
              alias Handler = mixin("execute_" ~ member);
              static if (member == "ldrsh_imm_t1") {}
              alias P = Parameters!(Handler!(vm_t));
              //pragma(msg, "Handler execute_" ~ member ~ " signature:");
              foreach (i, T; P) {
                   //pragma(msg, "  param " ~ i.stringof ~ ": " ~ T.stringof);
              //pragma(msg, "  returns: " ~ ReturnType!(Handler!(vm_t)).stringof);
              }
              static if (__traits(compiles, Handler!(vm_t)(instr, vm)))
              {
                  //pragma(msg, "Handler callable with this instruction type: execute_" ~ member);
                  Handler!(vm_t)(instr, vm);
                  handled = true;
                  break;
              }
              else
              {
                  assert(0, "Handler exists but wrong signature: execute_" ~ member);
              }
          }
          else
          {
              static assert(0, "Missing handler: execute_" ~ member);
          }
      }
  }
  if (vm.check_pc_modified()) 
  	return;
  static if (is(t == instr_16))
      vm.increment_pc(2);
  else static if (is(t == instr_32))
      vm.increment_pc(4);
  else
      static assert(0, "Unknown instruction type");
}

version (ARMv8_M) {
enum uint MAX_OVERLAPPING_INSTRS = 2;
struct inst_info_t {
  uint op;
  uint len;
  bool valid;
}

inst_info_t[MAX_OVERLAPPING_INSTRS] inst_info;
}

pragma(inline, true)
auto 
get_val(string reg_name, string bit_name, vm_t)
(ref vm_t vm, uint index) {
    alias getter_fn = uint function(ref vm_t);
    
    static immutable getter_fn[8] getters = () {
        getter_fn[8] result;
        static foreach (i; 0 .. 8) {{
            mixin(format("result[%d] = (ref vm_t v) => cast(uint) GET_%s%d_%s(v);", 
                i, reg_name, i, bit_name));
        }}
        return result;
    }();

    return getters[index](vm);
}

pragma(inline, true)
auto 
get_bit_val(string reg_name, string bit_name, vm_t)
(ref vm_t vm, uint index) {
    alias getter_fn = uint function(ref vm_t);
    
    static immutable getter_fn[8] getters = () {
        getter_fn[8] result;
        static foreach (i; 0 .. 8) {{
            mixin(format("result[%d] = (ref vm_t v) => cast(uint) GET_%s_%s%d(v);", 
                i, reg_name, bit_name, i));
        }}
        return result;
    }();

    return getters[index](vm);
}

pragma(inline, true)
auto get_val(string reg_name, vm_t)(ref vm_t vm, uint index) {
    alias getter_fn = uint function(ref vm_t);
    
    static immutable getter_fn[8] getters = () {
        getter_fn[8] result;
        static foreach (i; 0 .. 8) {{
            mixin(format("result[%d] = (ref vm_t v) => cast(uint) v.read_word(%s%d);", 
                i, reg_name, i));
        }}
        return result;
    }();

    return getters[index](vm);
}

pragma(inline, true)
void set_val(string reg_name, string bit_name, vm_t)
    (ref vm_t vm, uint index, uint val)
{
    alias setter_fn = void function(ref vm_t, uint);

    static immutable setter_fn[8] setters = () {
        setter_fn[8] result;

        static foreach (i; 0 .. 8) {{
            mixin(format(
                "result[%d] = (ref vm_t v, uint value) => SET_%s%d_%s(v, value);",
                i, reg_name, i, bit_name
            ));
        }}

        return result;
    }();

    setters[index](vm, val);
}

bool 
is_mve_access_fpscr_c
(vm_t)
(ref vm_t vm, uint instr) pure nothrow @nogc {
    const bool cp10_enabled = GET_CPACR_C10(vm) == 0b11;
    const bool cp11_enabled = GET_CPACR_C11(vm) == 0b11;
    if (!cp10_enabled || !cp11_enabled) {
        return false;
    }

    const bool is_vadc  = (instr & 0xFFF00F80) == 0xFE400E00;
    const bool is_vsbc  = (instr & 0xFFF00F80) == 0xFE400E40;
    const bool is_vshlc = (instr & 0xFFF00F80) == 0xFE400C80;

    return is_vadc || is_vsbc || is_vshlc;
}

// FPB_CheckMatchAddress
// =====================
// Flash Patch breakpoint instruction address comparison
bool 
fpb_check_match_addr
(vm_t)
(const uint addr, ref vm_t vm) {
  // FPB not enabled
  if (FP_CTRL_ENABLE_CLEAR(vm))
    return false;
  // Instruction Comparator.
  uint num_addr_cmp = (GET_FP_CTRL_NUM_CODE_HIGH(vm) << 4) | GET_FP_CTRL_NUM_CODE_LOW(vm);
  // No comparator support
  if (num_addr_cmp == 0)
    return false;
  foreach (n; 0 .. num_addr_cmp) {
    if (get_val!("FP_COMP", "BE")(vm, n) == 1)
      if (get_val!("FP_COMP", "BP_ADDR")(vm, n) == (addr & ~1))
        return true;
  }
  return false;
}

ubyte
get_epsr_eci
(vm_t)
(ref vm_t vm) {
  return cast(ubyte)((GET_EPSR_ECI_HIGH_HIGH(vm) << 6) | (GET_EPSR_ECI_HIGH(vm) << 2) | GET_EPSR_ECI_LOW(vm));
}

ubyte 
beat_complete
(vm_t)
(ref vm_t vm) {
  switch (get_epsr_eci(vm)) {
    case 0b0000_0000: return 0b0000_0000;
    case 0b0000_0001: return 0b0000_0001;
    case 0b0000_0010: return 0b0000_0011;
    case 0b0000_0100: return 0b0000_0111;
    case 0b0000_0101: return 0b0001_0111;
    default: break;
  }
  assert(0);
}

version (ARMv8_M) {
enum uint MAX_BEATS = 4;

// =====================
//  SetThisInstrDetails
// =====================

// SetThisInstrDetails(bits(32) opcode, integer len)
void set_this_instr_details(uint opcode, uint len) {
  // Insert the instruction into the queue at the first free slot. For
  // instruction with no beat behaviour this should always be the first slot.
  // NOTE: MVE instructions in IT blocks do not have beat wise execution.
  uint i = 0;
  // isBeatInst = IsMveBeatWiseInstruction(opcode) && !InITBlock();
  bool is_beat_instr = true;
  bool empty_slot;
  do {
    empty_slot = !inst_info[i].valid;
    if (empty_slot && (is_beat_instr || i == 0)) {
      inst_info[i].valid = true;
      inst_info[i].len   = len;
      inst_info[i].op    = opcode;
    }
    i = i + 1;
  } while (empty_slot || (!is_beat_instr && i > 0) || (i >= MAX_OVERLAPPING_INSTRS));
}

uint
get_epsr_it
(vm_t)
(ref vm_t vm) {
  return (GET_EPSR_IT_HIGH(vm) << 6) | GET_EPSR_IT_LOW(vm);
}

instr_exec_state get_instr_exec_state
(vm_t)
(ref vm_t vm, uint next) {
  assert(next < MAX_BEATS);
  instr_exec_state state;
  state.fetch_addr           = vm.get_pc();
  state.it_state             = cast(ubyte)get_epsr_it(vm);
  // L, T166IND, BTI, LOBranchInfoValid
  //state.L                    = 0;
  //state.T16IND               = 0;
  state.bits                 = cast(ubyte)LO_BRANCH_INFO_LOW_VALID_SET(vm);
  state.loop_count           = vm.get_reg(reg.lr);
  return state;
}

uint get_active_chains
(vm_t)
(ref vm_t vm) {
  uint count = 0;
  foreach (i; 0 .. MAX_OVERLAPPING_INSTRS) {
    if (inst_info[i].valid)
      count = count + 1;
  }
  return count;
}

bool set_dwt_debug_event
(vm_t)
(ref vm_t vm, bool secure_match) {
  SET_DHCSR_C_HALT(vm, 1);
  SET_DFSR_DWTTRAP(vm, 1);
  return true;
}

bool 
can_pend_monitor_on_event
(vm_t)
(ref vm_t vm, bool is_secure, bool check_pri, bool check_en, bool check_secure) {
  bool result;
  if (check_en) {
    result = result && ((GET_DEMCR_MON_EN(vm) == 1) || (GET_DEMCR_UMON_EN(vm) == 1) && !vm.current_mode_is_privileged());
  }

  return result;
}

// ===================================
//  IsLoadStoreClearMultInstruction()
// ===================================
// Checks whether the instruction is a clear multiple or a load / store multiple
bool is_load_store_clear_mult_instr(const uint instr) {
  // '00000000000000001100xxxxxxxxxxxx', // LDM_T1,STM_T1
  // '00000000000000001011x10xxxxxxxxx', // LDM_T3,STM_T2, and aliases
  // '1110100xx0xxxxxxxxxxxxxxxxxxxxxx', // Load/store/clear mul Scalar
  // '1110110xxxxxxxxxxxxx101xxxxxxxxx'; // Load/store/clear mul FP
  bool is_lscm = matches(instr, 0b11111111111111111111000000000000, 
                                0b00000000000000001100000000000000) ||
                 matches(instr, 0b11111111111111111011011000000000, 
                                0b00000000000000001011010000000000) ||
                 matches(instr, 0b11111110010000000000000000000000, 
                                0b11101000000000000000000000000000) ||
                 matches(instr, 0b11111110000000000000111000000000, 
                                0b11101100000000000000101000000000);
  // False positives due to the masks used in isLSCM
  // '1110100000xxxxxxxxxxxxxxxxxxxxxx',  // UNALLOCATED
  // '1110100110xxxxxxxxxxxxxxxxxxxxxx',  // UNALLOCATED
  // '11101100010xxxxxxxxx101x00x1xxxx',  // UNALLOCATED
  // '11101100010xxxxxxxxx101xxxx0xxxx',  // UNALLOCATED
  // '11101100000xxxxxxxxx101xxxxxxxxx',  // UNALLOCATED
  // '111011011x1xxxxxxxxx101xxxxxxxxx'}; // VMOV
  bool not_lscm = matches(instr, 0b11111111110000000000000000000000, 
                                 0b11101000000000000000000000000000) ||
                  matches(instr, 0b11111111110000000000000000000000, 
                                 0b11101001100000000000000000000000) ||
                  matches(instr, 0b11111111111000000000111011010000, 
                                 0b11101100010000000000101000010000) ||
                  matches(instr, 0b11111111111000000000111000010000, 
                                 0b11101100010000000000101000000000) ||
                  matches(instr, 0b11111111111000000000111000000000, 
                                 0b11101100000000000000101000000000) ||
                  matches(instr, 0b11111111101000000000111000000000, 
                                 0b11101101101000000000101000000000);
  return (is_lscm && !not_lscm);
}

// ==================
//  InstStateCheck()
// ==================

bool 
inst_state_check
(vm_t)
(ref vm_t vm, const uint instr) {
  // Check for IT,ICI,ECI bits that are not permitted for the current
  // instruction. NOTE EPSR.ICI and EPSR.ECI overlap with EPSR.IT.
  // validICI = (EPSR.ICI[7:6] == Zeros(2) && EPSR.ICI[1:0] == Zeros(2));
  bool valid_ici = (slice(GET_EPSR_ICI(vm), 6, 2) == 0) && (slice(GET_EPSR_ICI(vm), 0, 2) == 0);
  // validECI = UInt(EPSR.ECI) < 6 && EPSR.ECI[3:0] != '0011';
  bool valid_eci = (GET_EPSR_ECI(vm) < 6) && (slice(GET_EPSR_ECI(vm), 0, 4) != 0b0011);
  bool valid     = (vm.in_it_block() ||
                    GET_EPSR_IT(vm) == 0 ||
                   (valid_ici && (is_load_store_clear_mult_instr(instr) ||
                                  is_bkpt_instr(instr))) ||
                   (valid_eci && true /* (IsMveBeatWiseInstruction(instr) */) ||
                   (decode_mnemonic(instr) == opcode.le_t1) ||
                    is_bkpt_instr(instr));
  if (!valid) {
    SET_UFSR_INVSTATE(vm, 1);
    // excInfo = CreateException(UsageFault);
    //HandleException(excInfo);
  }
  return valid;
}
}

// =====================
//  IsBKPTInstruction()
// =====================
// Checks whether the instruction is a breakpoint

bool is_bkpt_instr(const uint instr) {
  return matches(instr, 0b1111_1111_1111_1111_1111_1111_0000_0000,
                        0b0000_0000_0000_0000_1011_1110_0000_0000);
}

// ======================
//  DWT_AddressCompare()
// ======================
// Returns a pair of values. The first result is whether the (masked) addresses are equal,
// where the access address (addr) is masked according to DWT_FUNCTION[n].DATAVSIZE and the
// comparator address (compaddr) is masked according to the access size. The second result
// is whether the (unmasked) addr is greater than the (unmasked) compaddr.
uint align_(const uint addr, const size_t size) {
  return cast(uint)(size * (addr / size));
}

Tuple!(bool,bool) dwt_addr_cmp(const uint addr, const uint cmp_addr, size_t size, size_t cmp_size) {
  // addr must be a multiple of size. Unaligned accesses are split into smaller accesses.
  assert(align_(addr, size) == addr);
  //compaddr must be a multiple of compsize
  //if Align(compaddr, compsize) != compaddr then UNPREDICTABLE;
  bool addr_match = (align_(addr, cmp_size) == align_(cmp_addr, size));
  bool addr_greater = (addr > cmp_addr);
  return tuple(addr_match, addr_greater);
}

// ===============================
//  DWT_InstructionAddressMatch()
// =============================
// Check for match of instruction access at "Iaddr".
// If comparators 'm' and 'm+1' form an Instruction Address Range comparator, then this
// function returns the range match when N=m+1.
bool 
dwt_instr_addr_match
(vm_t)
(const uint N, const uint iaddr, ref vm_t vm) {
  assert((N < GET_DWT_CTL_NUMCOMP(vm)) && (align_(iaddr, 2) == iaddr));
  bool match_eq, match_gt;
  bool lower_eq, lower_gt;
  bool match_addr;
  bool match;
  // secure_match = IsSecure();
  // valid_match = DWT_ValidMatch(N, secure_match);
  bool valid_instr = ((get_val!("DWT_FUNCTION", "MATCH")(vm, N) & 0b1110) == 0b0010);
  if (/*valid_match &&*/ valid_instr) {
    bool linked_to_instr;
    if (N != (GET_DWT_CTL_NUMCOMP(vm) - 1)) {
      linked_to_instr = (get_val!("DWT_FUNCTION", "MATCH")(vm, N + 1) == 0b0011);
    } else 
      linked_to_instr = false;
    bool linked;
    if (get_val!("DWT_FUNCTION", "MATCH")(vm, N) == 0b0011) {
      linked = true;
    } else
      linked = false;
    
    if (!linked_to_instr) {
      auto match_res0 = dwt_addr_cmp(iaddr, get_val!("DWT_COMP")(vm, N), 2, 2);
      match_eq = match_res0[0];
      match_gt = match_res0[1];
      if (linked) {
        //valid_match = DWT_ValidMatch(N-1, secure_match);
        auto match_res1 = dwt_addr_cmp(iaddr, get_val!("DWT_COMP")(vm, N-1), 2, 2);
        lower_eq = match_res1[0];
        lower_gt = match_res1[1];
        match_addr = (/*valid_match &&*/ (lower_eq || lower_gt) && !match_gt);
      } else
        match_addr = match_eq;
    } else
      match_addr = false;
    match = match_addr;
  } else
    match = false;
  return match;
}

// ========================
//  DWT_InstructionMatch()
// ========================
// Perform various Instruction Address checks for DWT

void 
dwt_instr_match
(vm_t)
(const uint iaddr, ref vm_t vm) {
  bool trigger_debug_event = false;
  bool debug_event = false;

  if (/*!HaveDWT() ||*/ GET_DWT_CTL_NUMCOMP(vm) == 0) // No comparator support
    return;
  foreach (i; 0 .. GET_DWT_CTL_NUMCOMP(vm)) {
    // if IsDWTConfigUnpredictable(i) then UNPREDICTABLE;
    // instr_addr_match = DWT_InstructionAddressMatch(i, Iaddr);
    bool instr_addr_match = dwt_instr_addr_match(i, iaddr, vm);
    // if instr_addr_match then
    // Instruction Address
    if (instr_addr_match) {
      if (get_val!("DWT_FUNCTION", "MATCH")(vm, i) == 0b0010) {
        set_val!("DWT_FUNCTION", "MATCHED")(vm, i, 1);
        debug_event = (get_val!("DWT_FUNCTION", "ACTION")(vm, i) == 0b01);
    // Instruction Address Limit
      } else if (get_val!("DWT_FUNCTION", "MATCH")(vm, i) == 0b0011) {
        //DWT_FUNCTION[i].MATCHED = bit UNKNOWN;
        set_val!("DWT_FUNCTION", "MATCHED")(vm, i - 1, 1);
        debug_event = (get_val!("DWT_FUNCTION", "ACTION")(vm, i - 1) == 0b01);
      }
    }
  }
    
  trigger_debug_event = trigger_debug_event || debug_event;
  if (trigger_debug_event) {
    //debug_event = SetDWTDebugEvent(IsSecure());
    return;
  }
}

version (ARMv8_M) {
void 
execute_instr_v8
(vm_t,t)
(const t instr, ref vm_t vm) {
  // Attempt to execute the next instruction. Start by setting up the state.
  vm.set_inst_id(0);
  vm.set_beat_id(0);
  uint active_chains = get_active_chains(vm);
  vm.set_curr_instr_exec_state(get_instr_exec_state(vm, active_chains));
  // auto curr_exec_state = vm.get_curr_exec_state(active_chains);
  bool commit_state = false;
  // Fetch the instruction
  // pc = ThisInstrAddr();
  uint pc = vm.get_this_instr_addr();
  bool bp = fpb_check_match_addr(pc, vm);


  // if ((Elem[beatStatus, instId, MAX_BEATS] != Zeros(MAX_BEATS))
  ubyte beat_status = beat_complete(vm);
  if (elem!(ubyte,ubyte)(beat_status, vm.get_inst_id(), MAX_BEATS) != 0) {
    return;
  }
  bool fetch_new = true;
  if (fetch_new) {
    execute_instr(instr, vm);
  }
  //dwt_instr_match(vm.get_pc(), vm);
}
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

string cpu_diff(const ref cortex_m_cpu a, const ref cortex_m_cpu b)
{
    auto buf = appender!string();

    foreach (i; 0 .. 16)
    {
        auto ra = a.core_registers[i];
        auto rb = b.core_registers[i];

        if (ra != rb)
            buf ~= format("r%-2d : 0x%08X vs 0x%08X\n", i, ra, rb);
    }

    foreach (i; 0 .. 32)
    {
        auto sa = a.fp_registers[i];
        auto sb = b.fp_registers[i];

        if (sa != sb)
            buf ~= format("s%-2d : 0x%08X vs 0x%08X\n", i, sa, sb);
    }

    if (a.get_sp() != b.get_sp())
        buf ~= format("sp  : 0x%08X vs 0x%08X\n", a.get_sp(), b.get_sp());

    if (a.get_pc() != b.get_pc())
        buf ~= format("pc  : 0x%08X vs 0x%08X\n", a.get_pc(), b.get_pc());

    if (a.n != b.n) buf ~= format("N   : %s vs %s\n", a.n, b.n);
    if (a.z != b.z) buf ~= format("Z   : %s vs %s\n", a.z, b.z);
    if (a.c != b.c) buf ~= format("C   : %s vs %s\n", a.c, b.c);
    if (a.v != b.v) buf ~= format("V   : %s vs %s\n", a.v, b.v);

    return buf.data;
}

string mem_diff(const ref tiny_mem a, const ref tiny_mem  b)
{
    auto buf = appender!string();

    foreach (i; 0 .. 1020)
    {
        if ((i & 3) != 0)   
          continue;
        auto va = a.read_word(i);
        auto vb = b.read_word(i);

        if (va != vb)
            buf ~= format("%d : 0x%08X vs 0x%08X\n", i, va, vb);
    }

    return buf.data;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

cortex_m_cpu make_cpu(T...)(T args)
{
    cortex_m_cpu cpu;

    foreach (arg; args)
    {
        static if (is(typeof(arg[0]) == reg)) {
          static if (is(typeof(arg[1]) == u128)) {
            if ((arg[0] >= reg.q0) && (arg[0] <= reg.q7))
              cpu.set_reg_q(arg[0], arg[1]);
            else 
              assert(0, "make_cpu: not a recognised register");
          } else {
            if ((arg[0] >= reg.r0) && (arg[0] <= reg.pc))
              cpu.set_reg(arg[0], arg[1]);
            else if ((arg[0] >= reg.s0) && (arg[0] <= reg.s31))
              cpu.set_reg_s(arg[0], arg[1]);
            else if ((arg[0] >= reg.d0) && (arg[0] <= reg.d15))
              cpu.set_reg_d(arg[0], arg[1]);
            else 
              assert(0, "make_cpu: not a recognised register");
          }
        }   
              
        static if (is(typeof(arg[0]) == flag))
            cpu.set_flag(arg[0], arg[1]);
        static if (is(typeof(arg[0]) == condition))
            cpu.it_block_stack.insertBack(arg[0]);
    }

    return cpu;
}

tiny_mem make_mem(T...)(T args)
{
    tiny_mem mem;

    foreach (arg; args)
    {
        mem.write_word(arg[0], arg[1]);
    }

    return mem;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    struct test_case {
        uint instr_bytes;
        instr_32 instr;
        test_vm before;
        test_vm expected;
    }

    test_case[] tests = [
        test_case(0xeb0101a3, instr_32(op: opcode.add_reg_t3, rd: reg.r1, rn: reg.r1, rm: reg.r3, shift_t: shift_type.asr, shift_n: 2), // add.w  r1, r1, r3, asr #2
                  test_vm(cpu: make_cpu(tuple(reg.r1, 0b011), tuple(reg.r3, 0b1100))                                                 ),
                  test_vm(cpu: make_cpu(tuple(reg.r1, 0b110), tuple(reg.r3, 0b1100), tuple(reg.pc, 4u)))),
        test_case(0xea010808, // and.w  r8, r1, r8 
                  instr_32(op: opcode.and_reg_t2, rd: reg.r8, rn: reg.r1, rm: reg.r8),
                  test_vm(cpu: make_cpu(tuple(reg.r8, 0b1100), tuple(reg.r1, 0b0111))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,     4u), tuple(reg.r8, 0b0100), tuple(reg.r1, 0b0111)))),
        test_case(0xf7ffbfbb, // b.w    8009c5c <_fclose_r>
                  instr_32(op: opcode.b_t4, offset:  -138),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 140))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,   6)))),
        test_case(0xea23030c, // bic.w  r3, r3, ip
                  instr_32(op: opcode.bic_reg_t2, rd: reg.r3, rn: reg.r3, rm: reg.r12),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 0b1100), tuple(reg.r12, 0b0100))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,     4u), tuple(reg.r3,  0b1000), tuple(reg.r12, 0b0100)))),
        test_case(0xf7ffffda,
                  instr_32(op: opcode.bl_t1, offset:  -76),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 88u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 16u), tuple(reg.lr, 93u)))),
        test_case(0xf3af8000, 
                  instr_32(op: opcode.nop_t2),
                  test_vm(),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u)))),
        test_case(0xf5a33a80, //  sub.w   sl, r3, #65536  @ 0x10000
                  instr_32(op: opcode.sub_imm_t3, rd: reg.r10, rn: reg.r3, imm: 65536),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 65537u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 65537u), tuple(reg.r10, 1)))),
        test_case(0xf008ff15, 
                  instr_32(op: opcode.bl_t1, offset:  36394),
                  test_vm(cpu: make_cpu(tuple(reg.pc,    1u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 36399), tuple(reg.lr, 5)))),
        test_case(0xf009f8a6,  
                  instr_32(op: opcode.bl_t1, offset:  37196),
                  test_vm(cpu: make_cpu(tuple(reg.pc,    1u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 37201), tuple(reg.lr, 5)))),
        test_case(0xf003030c, // and.w  r3, r3, #12
                  instr_32(op: opcode.and_imm_t1, rd: reg.r3, rn: reg.r3, unexpanded_imm: 12),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 0b0101))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,     4u), tuple(reg.r3, 0b0100)))),
        test_case(0xfbb2f3f3, // udiv   r3, r2, r3
                  instr_32(op: opcode.udiv_t1, rd: reg.r3, rn: reg.r2, rm: reg.r3),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 2u), tuple(reg.r3, 2u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r2, 2u), tuple(reg.r3, 1u)))),
        test_case(0xf3c20208, // ubfx   r2, r2, #0, #9
                  instr_32(op: opcode.ubfx_t1, rd: reg.r2, rn: reg.r2, lsb: 0, widthm1: 8),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 0xffff))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,     4u), tuple(reg.r2, 0x01ff)))),
        test_case(0xfb02f303, // mul.w  r3, r2, r3
                  instr_32(op: opcode.mul_t2, rd: reg.r3, rn: reg.r2, rm: reg.r3),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 4u), tuple(reg.r2, 2u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 8u), tuple(reg.r2, 2u)))),
        test_case(0xfa22f303, // lsr.w  r3, r2, r3
                  instr_32(op: opcode.lsr_reg_t2, rd: reg.r3, rn: reg.r2, rm: reg.r3, shift_t: shift_type.lsr),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 0b1100), tuple(reg.r3,     1u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,     4u), tuple(reg.r2, 0b1100), tuple(reg.r3, 0b0110)))),
        test_case(0xf4434380, // orr.w  r3, r3, #16384  @ 0x4000
                  instr_32(op: opcode.orr_imm_t1, rd: reg.r3, rn: reg.r3, unexpanded_imm: 16384, imm: 16384),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 0x0001))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 0x4001)))),
        test_case(0xf1070314, // add.w  r3, r7, #20
                  instr_32(op: opcode.add_imm_t3, rd: reg.r3, rn: reg.r7, imm: 20),
                  test_vm(cpu: make_cpu(tuple(reg.r7, 10u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 30u), tuple(reg.r7, 10u)))),
        test_case(0xf0230310, // bic.w  r3, r3, #16
                  instr_32(op: opcode.bic_imm_t1, rd: reg.r3, rn: reg.r3, imm: 16, unexpanded_imm: 16), // 0001 0000
                  test_vm(cpu: make_cpu(tuple(reg.r3, 17u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 1u)))),
        test_case(0xf64f03ff, // movw   r3, #63743  @ 0xf8ff
                  instr_32(op: opcode.mov_imm_t3, rd: reg.r3, imm: 63743),
                  test_vm(),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 0xf8ff)))),
        test_case(0xf3bf8f4f, 
                  instr_32(op: opcode.dsb_t1),
                  test_vm(),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u)))),
        test_case(0xf1c30307, // rsb    r3, r3, #7
                  instr_32(op: opcode.rsb_imm_t2, rd: reg.r3, rn: reg.r3, imm: 7),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 2u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3, 5u)))),
        test_case(0xfba22303, // umull  r2, r3, r2, r3
                  instr_32(op: opcode.umull_t1, rd_lo: reg.r2, rd_hi: reg.r3, rn: reg.r2, rm: reg.r3),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 10u), tuple(reg.r3, 5u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,  4u), tuple(reg.r2, 50u), tuple(reg.r3, 0u)))),
        test_case(0xf67fae90, // bls.w  8004360
                  instr_32(op: opcode.b_t4, cond: condition.ls, offset: -736),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 740u), tuple(flag.z, true), tuple(flag.c, false))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,   8u), tuple(flag.z, true), tuple(flag.c, false)))),
        test_case(0xea4161d2, // orr.w  r1, r1, r2, lsr #27
                  instr_32(op: opcode.orr_reg_t2, rd: reg.r1, rn: reg.r1, rm: reg.r2, shift_t: shift_type.lsr, shift_n: 27),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 0x40000000), tuple(reg.r1,         2u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,         4u), tuple(reg.r2, 0x40000000), tuple(reg.r1, 10u)))),
        test_case(0xf06f0240, // mvn.w  r2, #64 @ 0x40 
                  instr_32(op: opcode.orn_imm_t1, rd: reg.r2, imm: 64, unexpanded_imm: 64), 
                  test_vm(),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r2, -65)))),
        test_case(0xfb0e7711, // mls    r7, lr, r1, r7
                  instr_32(op: opcode.mls_t1, rd: reg.r7, rn: reg.lr, rm: reg.r1, ra: reg.r7),
                  test_vm(cpu: make_cpu(tuple(reg.r7, 20u), tuple(reg.r1,  2u), tuple(reg.lr, 3u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,  4u), tuple(reg.r7, 14u), tuple(reg.r1, 2u), tuple(reg.lr, 3u)))),
        test_case(0xea1c0f0e, // tst.w  ip, lr
                  instr_32(op: opcode.tst_reg_t2, rn: reg.r12, rm: reg.lr, shift_t: shift_type.lsl),
                  test_vm(cpu: make_cpu(tuple(reg.r12, 0b1111), tuple(reg.lr,  0b1111))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,      4u), tuple(reg.r12, 0b1111), tuple(reg.lr, 0b1111)))),
        test_case(0xebb2080a, // subs.w r8, r2, sl
                  instr_32(op: opcode.sub_reg_t2, rd: reg.r8, rn: reg.r2, rm: reg.r10, shift_t: shift_type.lsl, shift_n: 0),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 10u), tuple(reg.r10, 5u))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,  4u), tuple(reg.r8,  5u), tuple(reg.r2, 10u),   tuple(reg.r10, 5u)))),
        test_case(0xeb63090b, // sbc.w  r9, r3, fp
                  instr_32(op: opcode.sbc_reg_t2, rd: reg.r9, rn: reg.r3, rm: reg.r11, shift_t: shift_type.lsl, shift_n: 0),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 10u), tuple(reg.r11, 5u), tuple(flag.c, true))),
                  test_vm(cpu: make_cpu(tuple(reg.pc,  4u), tuple(reg.r9,  5u), tuple(reg.r3,  10u),  tuple(reg.r11,  5u), tuple(flag.c, true)))),
        test_case(0xeb45030b, // adc.w  r3, r5, fp
                  instr_32(op: opcode.adc_reg_t2, rd: reg.r3, rn: reg.r5, rm: reg.r11, shift_t: shift_type.lsl, shift_n: 0),
                  test_vm(cpu: make_cpu(tuple(reg.r5, 5u), tuple(reg.r11,  5u), tuple(flag.c,  true))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4u), tuple(reg.r3,  11u), tuple(reg.r11,   5u), tuple(reg.r5,   5u), tuple(flag.c, true)))),
        test_case(0xfaa4f28c, // sel r2, r4, ip
                  instr_32(op: opcode.sel_t1, rd: reg.r2, rn: reg.r4, rm: reg.r12),
                  test_vm(cpu: make_cpu(tuple(reg.r4, 0x778899aa), tuple(reg.r12, 0xbbccddee),
                                        tuple(flag.ge0, true), tuple(flag.ge2, true))),
                  test_vm(cpu: make_cpu(tuple(reg.r2,  0xbb88ddaa),
                                        tuple(reg.pc,  4),
                                        tuple(reg.r4,  0x778899aa),
                                        tuple(reg.r12, 0xbbccddee),
                                        tuple(flag.ge0, true), tuple(flag.ge2, true)))),
        test_case(0xfa50f383, // uxtab r3, r0, r3
                  instr_32(op: opcode.uxtab_t1, rd: reg.r3, rn: reg.r0, rm: reg.r3),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 0xccaa), tuple(reg.r0, 0xbb00))),
                  test_vm(cpu: make_cpu(tuple(reg.r3, 0xbbaa), tuple(reg.r0, 0xbb00),
                                        tuple(reg.pc, 4)))),
        test_case(0xfa90f3a0, // rbit  r3, r0
                  instr_32(op: opcode.rbit_t2, rd: reg.r3, rm: reg.r0),
                  test_vm(cpu: make_cpu(tuple(reg.r0, 0x89abcdef))),
                  test_vm(cpu: make_cpu(tuple(reg.r0, 0x89abcdef),
                                        tuple(reg.r3, 0xf7b3d591),
                                        tuple(reg.pc, 4)))),
        test_case(0xfab2f282, //clz r2, r2
                  instr_32(op: opcode.clz_t1, rd: reg.r2, rm: reg.r2),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 0x3aa))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4), tuple(reg.r2, 22)))),
        test_case(0xfa1ffe8c, //uxth.w  lr, ip
                  instr_32(op: opcode.uxth_t2, rd: reg.lr, rm: reg.r12),
                  test_vm(cpu: make_cpu(tuple(reg.r12, 0xeeeeffff))),
                  test_vm(cpu: make_cpu(tuple(reg.r12, 0xeeeeffff),
                                        tuple(reg.pc,  4),
                                        tuple(reg.lr,  0x0000ffff)))),
        test_case(0xfa5ffc8c, // uxtb.w ip, ip
                  instr_32(op: opcode.uxtb_t2, rd: reg.r12, rm: reg.r12),
                  test_vm(cpu: make_cpu(tuple(reg.r12, 0xeeeeeeff))),
                  test_vm(cpu: make_cpu(tuple(reg.r12, 0x000000ff),
                                        tuple(reg.pc,  4)))),
        test_case(0xf34000cf, // sbfx r0, r0, #3, #16
                  instr_32(op: opcode.sbfx_t1, rd: reg.r0, rn: reg.r0, lsb: 3, widthm1: 15),
                  test_vm(cpu: make_cpu(tuple(reg.r0, 0x0004cccf))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4),
                                        tuple(reg.r0, 0xffff9999)))),
        test_case(0xf0170f40, // tst.w r7, #64
                  instr_32(op: opcode.tst_imm_t1, rn: reg.r7, imm: 64, unexpanded_imm: 64),
                  test_vm(cpu: make_cpu(tuple(reg.r7, 0x40))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4),
                                        tuple(reg.r7, 0x40)))),
        test_case(0xfa98f898, // rev16.w r8, r8
                  instr_32(op: opcode.rev16_t2, rd: reg.r8, rm: reg.r8),
                  test_vm(cpu: make_cpu(tuple(reg.r8, 0xaabbccdd))),
                  test_vm(cpu: make_cpu(tuple(reg.r8, 0xbbaaddcc),
                                        tuple(reg.pc, 4)))),
        test_case(0xf36f0208, // bfc r2, #0, #9
                  instr_32(op: opcode.bfc_t1, rd: reg.r2, lsb: 0, msb: 8),
                  test_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffff))),
                  test_vm(cpu: make_cpu(tuple(reg.pc, 4),
                                        tuple(reg.r2, 0xfffffe00)))),
        test_case(0xfa4ff38a, // sxtb.w r3, sl
                  instr_32(op: opcode.sxtb_t2, rd: reg.r3, rm: reg.r10),
                  test_vm(cpu: make_cpu(tuple(reg.r10, 0x000000ee))),
                  test_vm(cpu: make_cpu(tuple(reg.r10, 0x000000ee),
                                        tuple(reg.pc,  4),
                                        tuple(reg.r3,  0xffffffee))))

    ];

    foreach (t; tests) {
        record_tested_opcode(t.instr.op);
        execute_instr(t.instr, t.before);
        assert(
            t.before == t.expected,
            format("Failed for instruction 0x%08X: %s", t.instr_bytes, cpu_diff(t.before.cpu, t.expected.cpu))
        );
    }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
  struct test_case {
    uint instr_bytes;
    instr_32 instr;
    tiny_vm before;
    tiny_vm expected;
  }

  test_case[] tests = [
    test_case(0xf8412023, // str.w  r2, [r1, r3, lsl #2]
              instr_32(op: opcode.str_reg_t2, rt: reg.r2, rn: reg.r1, rm: reg.r3, shift_t: shift_type.lsl, shift_n: 2),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffee), tuple(reg.r1, 10),         tuple(reg.r3, 4))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc,         4u), tuple(reg.r2, 0xffffffee), tuple(reg.r1, 10), tuple(reg.r3, 4)),
                      mem: make_mem(tuple(26, 0xffffffee)))),
    test_case(0xe8533f00, // ldrex  r3, [r3]
              instr_32(op: opcode.ldrex_t1, rt: reg.r3, rn: reg.r3),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 2)),
                      mem: make_mem(tuple(2, 0xffffffee))),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xffffffee), tuple(reg.pc, 4u)),
                      mem: make_mem(tuple(2, 0xffffffee)))),
    test_case(0xe8412300, // strex  r3, r2, [r1]
              instr_32(op: opcode.strex_t1, rd: reg.r3, rt: reg.r2, rn: reg.r1),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffee), tuple(reg.r1, 2))),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffee), tuple(reg.r1, 2), tuple(reg.pc, 4u)),
                      mem: make_mem(tuple(2, 0xffffffee)))),
    test_case(0xe9c72300, // strd   r2, r3, [r7]
              instr_32(op: opcode.strd_imm_t1, rt: reg.r2, rt_2: reg.r3, rn: reg.r7),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffee), tuple(reg.r3, 0xffffffff), tuple(reg.r7, 4))),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffee), tuple(reg.r3, 0xffffffff), tuple(reg.r7, 4), tuple(reg.pc, 4u)),
                      mem: make_mem(tuple(4, 0xffffffee), tuple(8, 0xffffffff)))),
    test_case(0xf9b4500c, // ldrsh.w    r5, [r4, #12]
              instr_32(op: opcode.ldrsh_imm_t1, rt: reg.r5, rn: reg.r4, index: true, add: true, imm: 12),
              tiny_vm(cpu: make_cpu(tuple(reg.r4, 8)),
                      mem: make_mem(tuple(20, 2))),
              tiny_vm(cpu: make_cpu(tuple(reg.r5, 2), tuple(reg.r4, 8), tuple(reg.pc, 4)),
                      mem: make_mem(tuple(20, 2)))),
    test_case(0xf9973007, // ldrsb.w    r3, [r7, #7]
              instr_32(op: opcode.ldrsb_imm_t1, rt: reg.r3, rn: reg.r7, index: true, add: true, imm: 7),
              tiny_vm(cpu: make_cpu(tuple(reg.r7, 3)),
                      mem: make_mem(tuple(10, 0x000000ee))),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xffffffee), tuple(reg.r7, 3), tuple(reg.pc, 4)),
                      mem: make_mem(tuple(10, 0x000000ee)))),
    test_case(0xe8bd4008, 
              instr_32(op: opcode.pop_t2, reg_list: [reg.r3, reg.lr]),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base - 8)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0xffffffff), 
                                    tuple(tiny_mem.stack_base-8, 0xffffffee))),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base), tuple(reg.pc, 4), tuple(reg.r3, 0xffffffee),
                                    tuple(reg.lr, 0xffffffff)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0xffffffff), 
                                    tuple(tiny_mem.stack_base-8, 0xffffffee)))),
    test_case(0xf8dfd034, 
              instr_32(op: opcode.ldr_imm_t3, rt: reg.sp, rn: reg.pc, add: true, index: true, imm: 52),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 0)),
                      mem: make_mem(tuple(56, tiny_mem.stack_base))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 4), tuple(reg.sp, tiny_mem.stack_base)),
                      mem: make_mem(tuple(56, tiny_mem.stack_base)))),
    test_case(0xe92d4fb0, // stmdb  sp!, {r4, r5, r7, r8, r9, sl, fp, lr}
              instr_32(op: opcode.push_t2, reg_list: [reg.r4, reg.r5, reg.r7, reg.r8, reg.r9, reg.r10, reg.r11, reg.lr]),
              tiny_vm(cpu: make_cpu(tuple(reg.sp,   tiny_mem.stack_base), 
                                    tuple(reg.r4,  1), tuple(reg. r5, 2), 
                                    tuple(reg.r7,  3), tuple(reg. r8, 4), 
                                    tuple(reg.r9,  5), tuple(reg.r10, 6), 
                                    tuple(reg.r11, 7), tuple(reg. lr, 8))),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base-(8*4)), 
                                    tuple(reg.r4,  1), tuple(reg. r5, 2), 
                                    tuple(reg.r7,  3), tuple(reg. r8, 4), 
                                    tuple(reg.r9,  5), tuple(reg.r10, 6), 
                                    tuple(reg.r11, 7), tuple(reg. lr, 8),
                                    tuple(reg.pc,  4)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4,      8), 
                                    tuple(tiny_mem.stack_base-8,      7), 
                                    tuple(tiny_mem.stack_base-12,     6), 
                                    tuple(tiny_mem.stack_base-16,     5), 
                                    tuple(tiny_mem.stack_base-20,     4), 
                                    tuple(tiny_mem.stack_base-24,     3), 
                                    tuple(tiny_mem.stack_base-28,     2), 
                                    tuple(tiny_mem.stack_base-32,     1)))),
    test_case(0xe8bd4070, // ldmia.w sp!, {r4, r5, r6, lr}
              instr_32(op: opcode.ldm_t2, rn: reg.sp, reg_list: [reg.r4, reg.r5, reg.r6, reg.lr], wback: true),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base-16)),
                      mem: make_mem(tuple(tiny_mem.stack_base-16, 1),
                                    tuple(tiny_mem.stack_base-12, 2),
                                    tuple(tiny_mem.stack_base-8,  3),
                                    tuple(tiny_mem.stack_base-4,  4))),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base),
                                    tuple(reg.pc, 4),
                                    tuple(reg.lr, 4),
                                    tuple(reg.r6, 3),
                                    tuple(reg.r5, 2),
                                    tuple(reg.r4, 1)),
                      mem: make_mem(tuple(tiny_mem.stack_base-16, 1),
                                    tuple(tiny_mem.stack_base-12, 2),
                                    tuple(tiny_mem.stack_base-8,  3),
                                    tuple(tiny_mem.stack_base-4,  4)))),
    test_case(0xe8ac00f, // stmia.w ip!, {r0, r1, r2, r3}
              instr_32(op: opcode.stm_t2, rn: reg.r12, reg_list: [reg.r0, reg.r1, reg.r2, reg.r3], wback: true),
              tiny_vm(cpu: make_cpu(tuple(reg.r12, tiny_mem.stack_base-16),
                                    tuple(reg.r0, 1),
                                    tuple(reg.r1, 2),
                                    tuple(reg.r2, 3),
                                    tuple(reg.r3, 4))),
              tiny_vm(cpu: make_cpu(tuple(reg.r12, tiny_mem.stack_base),
                                    tuple(reg.pc, 4),
                                    tuple(reg.r0, 1),
                                    tuple(reg.r1, 2),
                                    tuple(reg.r2, 3),
                                    tuple(reg.r3, 4)),
                      mem: make_mem(tuple(tiny_mem.stack_base-16, 1),
                                    tuple(tiny_mem.stack_base-12, 2),
                                    tuple(tiny_mem.stack_base-8,  3),
                                    tuple(tiny_mem.stack_base-4,  4)))), 
      test_case(0xe9120007, // ldmdb r2, {r0, r1, r2}
                instr_32(op: opcode.ldmdb_t1, rn: reg.r2, reg_list: [reg.r0, reg.r1, reg.r2]),
                tiny_vm(cpu: make_cpu(tuple(reg.r2, tiny_mem.stack_base)),
                        mem: make_mem(tuple(tiny_mem.stack_base-12, 1),
                                      tuple(tiny_mem.stack_base-8,  2),
                                      tuple(tiny_mem.stack_base-4,  3))),
                tiny_vm(cpu: make_cpu(tuple(reg.pc, 4),
                                      tuple(reg.r0, 1),
                                      tuple(reg.r1, 2),
                                      tuple(reg.r2, 3)),
                        mem: make_mem(tuple(tiny_mem.stack_base-12, 1),
                                      tuple(tiny_mem.stack_base-8,  2),
                                      tuple(tiny_mem.stack_base-4,  3)))),
      test_case(0xe92d41f0, // stmdb sp!, {r4, r5, r6, r7, r8, lr}
                instr_32(op: opcode.stmdb_t1, rn: reg.sp, reg_list: [reg.r4, reg.r5, reg.r6, reg.r7, reg.r8, reg.lr], wback: true),
                tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base),
                                      tuple(reg.r4, 1),
                                      tuple(reg.r5, 2),
                                      tuple(reg.r6, 3),
                                      tuple(reg.r7, 4),
                                      tuple(reg.r8, 5),
                                      tuple(reg.lr, 6))),
                tiny_vm(cpu: make_cpu(tuple(reg.pc, 4),
                                      tuple(reg.sp, tiny_mem.stack_base-24),
                                      tuple(reg.r4, 1),
                                      tuple(reg.r5, 2),
                                      tuple(reg.r6, 3),
                                      tuple(reg.r7, 4),
                                      tuple(reg.r8, 5),
                                      tuple(reg.lr, 6)),
                        mem: make_mem(tuple(tiny_mem.stack_base-24, 1),
                                      tuple(tiny_mem.stack_base-20, 2),
                                      tuple(tiny_mem.stack_base-16, 3),
                                      tuple(tiny_mem.stack_base-12, 4),
                                      tuple(tiny_mem.stack_base-8,  5),
                                      tuple(tiny_mem.stack_base-4,  6)))), 
      test_case(0xf9156c62, // ldrsb.w r6, [r5, #-98]
                instr_32(op: opcode.ldrsb_imm_t2, rt: reg.r6, rn: reg.r5, index: true, imm: 98),
                tiny_vm(cpu: make_cpu(tuple(reg.r5, 200)),
                        mem: make_mem(tuple(100, 0x00ee0000))),
                tiny_vm(cpu: make_cpu(tuple(reg.r5, 200), 
                                      tuple(reg.r6, 0xffffffee), 
                                      tuple(reg.pc, 4)),
                        mem: make_mem(tuple(100, 0x00ee0000)))),

  ];

  version (ARMv8_M) {
  tests ~= [
    test_case(0xeea23b10, // vdup.32  q1, r3
              instr_32(op: opcode.vdup_t1, qd: reg.q1, rt: reg.r3, esize: 32, elements: 1),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xffeeffff))),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xffeeffff),
                                    tuple(reg.pc, 4), 
                                    tuple(reg.s4, 0xffeeffff)))),
  ];
}

  foreach (t; tests) {
      record_tested_opcode(t.instr.op);
      execute_instr(t.instr, t.before);
      assert(
          t.before == t.expected,
          format("Failed for instruction 0x%08X:\n %s\n %s", t.instr_bytes, cpu_diff(t.before.cpu, t.expected.cpu), mem_diff(t.before.mem, t.expected.mem))
      );
  }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
  struct test_case {
    ushort instr_bytes;
    instr_16 instr;
    test_vm before;
    test_vm expected;
  }

  test_case[] tests = [
    test_case(0x2b00,
          instr_16(op: opcode.cmp_imm_t1,       rn: reg.r3,               imm: 0),
          test_vm(),
          test_vm(cpu: make_cpu(tuple(reg.pc,   2u), tuple(flag.z, true), tuple(flag.c, true)))),
    test_case(0x10b6, // asrs r6, r6, #2
          instr_16(op: opcode.asr_imm_t1,       rd: reg.r6,  rm: reg.r6,  shift_t: shift_type.asr, imm: 2),
          test_vm(cpu: make_cpu(tuple(reg.r6, 0b10))),
          test_vm(cpu: make_cpu(tuple(reg.pc,   2u), tuple(reg.r6,    0), tuple(flag.z, true), tuple(flag.c, true)))),
    test_case(0x1076,
          instr_16(op: opcode.asr_imm_t1,       rd: reg.r6,  rm: reg.r6,  shift_t: shift_type.asr, imm: 1),
          test_vm(cpu: make_cpu(tuple(reg.r6, 0b10))),
          test_vm(cpu: make_cpu(tuple(reg.pc,    2), tuple(reg.r6,  0b1)))),
    test_case(0x3730, 
          instr_16(op: opcode.add_imm_t2,       rd: reg.r7,  rn: reg.r7,  imm: 48),
          test_vm(cpu: make_cpu(tuple(reg.r7, 0))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r7, 48)))),
    test_case(0x4013, 
          instr_16(op: opcode.and_reg_t1,       rd: reg.r3,  rn: reg.r3,  rm: reg.r2),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0b11100), tuple(reg.r2, 0b00111))),
          test_vm(cpu: make_cpu(tuple(reg.pc,       2), tuple(reg.r3, 0b00100),  tuple(reg.r2, 0b00111)))),
    test_case(0x2300, 
          instr_16(op: opcode.mov_imm_t1,       rd: reg.r3,               imm: 0),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0b111))),
          test_vm(cpu: make_cpu(tuple(reg.pc,     2),   tuple(reg.r3,   0b000),  tuple(flag.z, true)))),
    test_case(0x3902, 
          instr_16(op: opcode.sub_imm_t2,       rd: reg.r1,  rn: reg.r1,  imm: 2),
          test_vm(cpu: make_cpu(tuple(reg.r1, 0b0100))),
          test_vm(cpu: make_cpu(tuple(reg.pc,      2), tuple(reg.r1, 0b0010), tuple(flag.c, true)))),   
    test_case(0x00d9, 
          instr_16(op: opcode.lsl_imm_t1,       rd : reg.r1, rm: reg.r3,  shift_t: shift_type.lsl, imm: 3),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0x100001c0))),
          test_vm(cpu: make_cpu(tuple(reg.pc,          2), tuple(reg.r3, 0x100001c0), tuple(reg.r1, 0x80000e00), tuple(flag.n, true)))),
    test_case(0x099b, 
          instr_16(op: opcode.lsr_imm_t1,       rd: reg.r3,  rm: reg.r3,  shift_t: shift_type.lsr, imm: 6),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0x00007001))),
          test_vm(cpu: make_cpu(tuple(reg.pc,          2),   tuple(reg.r3, 0x000001c0)))),
    test_case(0x4313, 
          instr_16(op: opcode.orr_reg_t1,       rd: reg.r3,  rn: reg.r3, rm: reg.r2),
          test_vm(cpu: make_cpu(tuple(reg.r3,     0b1100),   tuple(reg.r2, 0b0011))),
          test_vm(cpu: make_cpu(tuple(reg.pc,          2),   tuple(reg.r3, 0b1111),   tuple(reg.r2, 0b0011)))),
    test_case(0x43db, 
          instr_16(op: opcode.mvn_reg_t1,       rd: reg.r3,  rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0x00007001))),
          test_vm(cpu: make_cpu(tuple(reg.pc,          2), tuple(reg.r3, 0xffff8ffe)))),
    test_case(0x4283, 
          instr_16(op: opcode.cmp_reg_t1,       rn: reg.r3,  rm: reg.r0),
          test_vm(),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(flag.z, true), tuple(flag.c, true)))),
    test_case(0xd002, 
          instr_16(op: opcode.b_t1,             cond: condition.eq,      offset: 4),
          test_vm(cpu: make_cpu(tuple(reg.pc, 10), tuple(flag.z, true))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 18), tuple(flag.z, true)))),
    test_case(0xb103, 
          instr_16(op: opcode.cbz_t1,           rn: reg.r3,              offset: 0),
          test_vm(cpu: make_cpu(tuple(reg.pc, 10))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 14)))),
    test_case(0x1a1b, 
          instr_16(op: opcode.sub_reg_t1,       rd: reg.r3,  rn: reg.r3, rm: reg.r0),
          test_vm(cpu: make_cpu(tuple(reg.r3, 10), tuple(reg.r0, 3))),
          test_vm(cpu: make_cpu(tuple(reg.pc,  2), tuple(reg.r3, 7), tuple(reg.r0, 3), tuple(flag.c, true)))),
    test_case(0xb943, 
          instr_16(op: opcode.cbnz_t1,     rn: reg.r3,        offset: 8),
          test_vm(cpu: make_cpu(tuple(reg.pc, 10), tuple(reg.r3, 1))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 22), tuple(reg.r3, 1)))),         
    test_case(0x469d, 
          instr_16(op: opcode.mov_reg_t2,    rd: reg.sp,  rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.sp, 10), tuple(reg.r3, 1))),
          test_vm(cpu: make_cpu(tuple(reg.pc,  2), tuple(reg.sp, 1), tuple(reg.r3, 1)))),
    test_case(0x460f, 
          instr_16(op: opcode.mov_reg_t1,        rd: reg.r7,  rm: reg.r1),
          test_vm(cpu: make_cpu(tuple(reg.r7, 10), tuple(reg.r1, 1))),
          test_vm(cpu: make_cpu(tuple(reg.pc,  2), tuple(reg.r7, 1), tuple(reg.r1, 1)))),
    test_case(0x4798, 
          instr_16(op: opcode.blx_t1,           rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.pc, 10), tuple(reg.r3, 20))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 20), tuple(reg.lr, 12), tuple(reg.r3, 20)))),
    test_case(0xaf00, 
          instr_16(op: opcode.add_sp_t1,        rd: reg.r7,         imm: 0),
          test_vm(cpu: make_cpu(tuple(reg.sp, 10), tuple(reg.r7, 20))),
          test_vm(cpu: make_cpu(tuple(reg.pc,  2), tuple(reg.sp, 10), tuple(reg.r7, 10)))),
    test_case(0xb092, 
          instr_16(op: opcode.sub_sp_t1,                 imm: 72),
          test_vm(cpu: make_cpu(tuple(reg.sp, 90))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.sp, 18)))),    
    test_case(0x1d3b, 
          instr_16(op: opcode.add_imm_t1,     rd: reg.r3,  rn: reg.r7, imm: 4),
          test_vm(cpu: make_cpu(tuple(reg.r3, 3), tuple(reg.r7, 4))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r3, 8), tuple(reg.r7, 4)))),
    test_case(0x4413, 
          instr_16(op: opcode.add_reg_t1,     rd: reg.r3,  rn: reg.r3, rm: reg.r2),
          test_vm(cpu: make_cpu(tuple(reg.r3, 3), tuple(reg.r2, 2))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r3, 5), tuple(reg.r2, 2)))),
    test_case(0x409a, 
          instr_16(op: opcode.lsl_reg_t1,       rd: reg.r2,  rn: reg.r2, rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.r2, 0b0101), tuple(reg.r3,       1))),
          test_vm(cpu: make_cpu(tuple(reg.pc,      2), tuple(reg.r2, 0b1010), tuple(reg.r3, 1)))),
    test_case(0xe001,
          instr_16(op: opcode.b_t2,   offset: 2),
          test_vm(cpu: make_cpu(tuple(reg.pc, 0x800a1b0))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 0x800a1b6)))),
    test_case(0x40da, 
          instr_16(op: opcode.lsr_reg_t1,       rd: reg.r2,  rn: reg.r2, rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.r2, 0b1010), tuple(reg.r3, 1))),
          test_vm(cpu: make_cpu(tuple(reg.pc,      2), tuple(reg.r2, 0b0101), tuple(reg.r3,1)))),
    test_case(0xa201, 
          instr_16(op: opcode.adr_t1,           rd: reg.r2,          imm: 4),
          test_vm(cpu: make_cpu(tuple(reg.r2, 10), tuple(reg.pc,  2))),
          test_vm(cpu: make_cpu(tuple(reg.r2,  8), tuple(reg.pc,  4)))),
    test_case(0x1891, 
          instr_16(op: opcode.add_reg_t1,     rd: reg.r1,  rn: reg.r2, rm: reg.r2),
          test_vm(cpu: make_cpu(tuple(reg.r1, 10), tuple(reg.r2, 10))),
          test_vm(cpu: make_cpu(tuple(reg.pc,  2), tuple(reg.r1, 20), tuple(reg.r2, 10)))),
    test_case(0xd3f9,
          instr_16(op: opcode.b_t1,      cond: condition.cc, offset: -14),
          test_vm(cpu: make_cpu(tuple(reg.pc, 0x800a1a8))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 0x800a19e)))),
    test_case(0x4572, 
          instr_16(op: opcode.cmp_reg_t2,  rn: reg.r2,  rm: reg.lr),
          test_vm(),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(flag.z, true), tuple(flag.c, true)))),
    test_case(0x1e54, 
          instr_16(op: opcode.sub_imm_t1,     rd: reg.r4,  rn: reg.r2, imm: 1),
          test_vm(cpu: make_cpu(tuple(reg.r4, 7), tuple(reg.r2, 9))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r4, 8), tuple(reg.r2, 9), tuple(flag.c, true)))),
    test_case(0x4463, 
          instr_16(op: opcode.add_reg_t2,     rd: reg.r3,  rn: reg.r3, rm: reg.r12),
          test_vm(cpu: make_cpu(tuple(reg.r3, 3), tuple(reg.r12, 4))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r3,  7), tuple(reg.r12, 4)))),
    test_case(0x44e6, 
          instr_16(op: opcode.add_reg_t2,     rd: reg.lr,  rn: reg.lr, rm: reg.r12),
          test_vm(cpu: make_cpu(tuple(reg.lr, 7), tuple(reg.r12, 9))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.lr, 16), tuple(reg.r12, 9)))),
    test_case(0x458c, 
          instr_16(op: opcode.cmp_reg_t2,    rn: reg.r12, rm: reg.r1),
          test_vm(),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(flag.z, true), tuple(flag.c, true)))),
    test_case(0x4241, 
          instr_16(op: opcode.rsb_imm_t1,      rd: reg.r1,  rn: reg.r0),
          test_vm(cpu: make_cpu(tuple(reg.r0, 1))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r1, -1), tuple(reg.r0, 1), tuple(flag.n, true)))),
    test_case(0x4652, 
          instr_16(op: opcode.mov_reg_t2,    rd: reg.r2,  rm: reg.r10),
          test_vm(cpu: make_cpu(tuple(reg.r2, 1), tuple(reg.r10, 3))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r2,  3), tuple(reg.r10, 3)))),
    test_case(0x4208, // tst  r0, r1
          instr_16(opcode.tst_reg_t1, rn: reg.r0, rm: reg.r1),
          test_vm(cpu: make_cpu(tuple(reg.r0, 0xaaaaaaaa), tuple(reg.r1, 0x55555555))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r0, 0xaaaaaaaa), 
                                                  tuple(reg.r1, 0x55555555), 
                                                  tuple(flag.z, true)))),
    test_case(0xba5b, // rev16 r3, r3
          instr_16(opcode.rev16_t1, rd: reg.r3, rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0xaabbccdd))),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0xbbaaddcc), tuple(reg.pc, 2)))),
    test_case(0x4393, // bics  r3, r2
          instr_16(opcode.bic_reg_t1, rd: reg.r3, rn: reg.r3, rm: reg.r2),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0x11111111),
                                tuple(reg.r2, 0xaaaa5555))),
          test_vm(cpu: make_cpu(tuple(reg.r3, 0xaaaa4444),
                                tuple(reg.r2, 0xaaaa5555),
                                tuple(flag.n, true),
                                tuple(reg.pc, 2)))),
    test_case(0xb209, // sxth r1, r1
          instr_16(op: opcode.sxth_t1, rd: reg.r1, rm: reg.r1),
          test_vm(cpu: make_cpu(tuple(reg.r1, 0x0000aa00))),
          test_vm(cpu: make_cpu(tuple(reg.r1, 0xffffaa00), tuple(reg.pc, 2)))),
    test_case(0xb2f4, // uxtb r4, r6
          instr_16(op: opcode.uxtb_t1, rd: reg.r4, rm: reg.r6),
          test_vm(cpu: make_cpu(tuple(reg.r6, 0xeeeeeeff))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                tuple(reg.r6, 0xeeeeeeff), 
                                tuple(reg.r4, 0x000000ff)))),
    test_case(0x4358, // muls r0, r3
              instr_16(op: opcode.mul_t1, rd: reg.r0, rn: reg.r3, rm: reg.r0),
              test_vm(cpu: make_cpu(tuple(reg.r3, -2), tuple(reg.r0, 3))),
              test_vm(cpu: make_cpu(tuple(reg.r0, 0xfffffffa),
                                    tuple(reg.r3, -2),
                                    tuple(reg.pc,  2),
                                    tuple(flag.n, true)))),
    test_case(0xb240, // sxtb r0, r0
              instr_16(op: opcode.sxtb_t1, rd: reg.r0, rm: reg.r0),
              test_vm(cpu: make_cpu(tuple(reg.r0, 0x000000ee))),
              test_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                    tuple(reg.r0, 0xffffffee)))),
    test_case(0xb005, // add sp, #20
              instr_16(op: opcode.add_sp_t2, rd: reg.sp, imm: 20),
              test_vm(),
              test_vm(cpu: make_cpu(tuple(reg.sp, 20), tuple(reg.pc, 2)))),
    test_case(0x2301, // movne r3, #1
              instr_16(op: opcode.mov_imm_t1, rd: reg.r3, imm: 1),
              test_vm(cpu: make_cpu(tuple(condition.eq, true))),
              test_vm(cpu: make_cpu(tuple(reg.pc, 2))))
  ];

  foreach (t; tests) {
      record_tested_opcode(t.instr.op);
      execute_instr(t.instr, t.before);
      assert(
          t.before == t.expected,
          format("Failed for instruction 0x%08X: %s", t.instr_bytes, cpu_diff(t.before.cpu, t.expected.cpu))
      );
  }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
  struct test_case {
    ushort instr_bytes;
    instr_16 instr;
    tiny_vm before;
    tiny_vm expected;
  }

  test_case[] tests = [
    test_case(0x4718, 
              instr_16(op: opcode.bx_t1,            rm: reg.r3),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 10), tuple(reg.pc,  0))),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 10), tuple(reg.pc, 10)))),
    test_case(0xbd10, 
              instr_16(op: opcode.pop_t1, reg_list: [reg.r4, reg.pc]),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base-8)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0x000000ee),
                                    tuple(tiny_mem.stack_base-8, 0x000000ff))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 0x000000ee),
                                    tuple(reg.r4, 0x000000ff),
                                    tuple(reg.sp, tiny_mem.stack_base)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0x000000ee),
                                    tuple(tiny_mem.stack_base-8, 0x000000ff)))),
    test_case(0xb510, 
              instr_16(op: opcode.push_t1, reg_list: [reg.r4, reg.lr]),
              tiny_vm(cpu: make_cpu(tuple(reg.sp, tiny_mem.stack_base), 
                                    tuple(reg.lr, 0x000000ff), 
                                    tuple(reg.r4, 0x000000ee))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2), 
                                    tuple(reg.sp, tiny_mem.stack_base-8), 
                                    tuple(reg.lr, 0x000000ff), 
                                    tuple(reg.r4, 0x000000ee)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0x000000ff), 
                                    tuple(tiny_mem.stack_base-8, 0x000000ee)))),
    test_case(0xc303,
              instr_16(op: opcode.stm_t1, rn: reg.r3, reg_list: [reg.r0, reg.r1]),
              tiny_vm(cpu: make_cpu(tuple(reg.r1, 0x000000ff), 
                                    tuple(reg.r0, 0x000000ee),
                                    tuple(reg.r3, tiny_mem.stack_base-8))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2), 
                                    tuple(reg.r3, tiny_mem.stack_base), 
                                    tuple(reg.r1, 0x000000ff), 
                                    tuple(reg.r0, 0x000000ee)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0x000000ff), 
                                    tuple(tiny_mem.stack_base-8, 0x000000ee)))),
    test_case(0xcc03,
              instr_16(op: opcode.ldm_t1, rn: reg.r3, reg_list: [reg.r0, reg.r1]),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, tiny_mem.stack_base - 8)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0xbb), 
                                    tuple(tiny_mem.stack_base-8, 0xaa))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                    tuple(reg.r3, tiny_mem.stack_base),
                                    tuple(reg.r0, 0xaa),
                                    tuple(reg.r1, 0xbb)),
                      mem: make_mem(tuple(tiny_mem.stack_base-4, 0xbb), 
                                    tuple(tiny_mem.stack_base-8, 0xaa)))),
    test_case(0x608b, 
              instr_16(op: opcode.str_imm_t1, rt: reg.r3, rn: reg.r1, imm: 8),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0b0101), 
                                    tuple(reg.r1, tiny_mem.ram_origin + 12))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc,      2), 
                                    tuple(reg.r3, 0b0101), 
                                    tuple(reg.r1, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(20, 0b101)))),
    test_case(0x50c4, // str  r4, [r0, r3]
              instr_16(op: opcode.str_reg_t1, rt: reg.r4, rn: reg.r0, rm: reg.r3),
              tiny_vm(cpu: make_cpu(tuple(reg.r4, 0xffffffff),
                                    tuple(reg.r3, 10), 
                                    tuple(reg.r0, tiny_mem.ram_origin))),
              tiny_vm(cpu: make_cpu(tuple(reg.r4, 0xffffffff), 
                                    tuple(reg.pc, 2), 
                                    tuple(reg.r3, 10), 
                                    tuple(reg.r0, tiny_mem.ram_origin)),
                      mem: make_mem(tuple(10, 0xffffffff)))),
    test_case(0x80fb, 
              instr_16(op: opcode.strh_imm_t1, rt: reg.r3,  rn: reg.r7, imm: 6),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0x0000eeee), tuple(reg.r7, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(16, 0xffffffff))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2), 
                                    tuple(reg.r3, 0x0000eeee), 
                                    tuple(reg.r7, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(16, 0xffffeeee)))),
    test_case(0x80fb, 
              instr_16(op: opcode.strh_imm_t1, rt: reg.r3,  rn: reg.r7, imm: 6),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0x0000eeee), tuple(reg.r7, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(16, 0xffffffff))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2), 
                                    tuple(reg.r3, 0x0000eeee), 
                                    tuple(reg.r7, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(16, 0xeeeeffff)))),
    test_case(0x88fb, 
              instr_16(op: opcode.ldrh_imm_t1, rt: reg.r3, rn: reg.r7, imm: 6),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xffffffff), 
                                    tuple(reg.r7, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(16, 0xffffeeee))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                    tuple(reg.r3, 0x0000eeee),
                                    tuple(reg.r7, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(16, 0xffffeeee)))),
    test_case(0x88fb, 
              instr_16(op: opcode.ldrh_imm_t1, rt: reg.r3, rn: reg.r7, imm: 6),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xffffffff), 
                                    tuple(reg.r7, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(16, 0xffffeeee))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                    tuple(reg.r3, 0x0000ffff),
                                    tuple(reg.r7, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(16, 0xffffeeee)))),
    test_case(0x781a, 
              instr_16(op: opcode.ldrb_imm_t1, rt: reg.r2,  rn: reg.r3, imm: 0),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0xffffffff), 
                                    tuple(reg.r3, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(8, 0x00ee0000))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2), 
                                    tuple(reg.r2, 0x000000ee), 
                                    tuple(reg.r3, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(8, 0x00ee0000)))),
    test_case(0x701a, 
              instr_16(op: opcode.strb_imm_t1, rt: reg.r2, rn: reg.r3, imm: 0),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, 0x000000ee), 
                                    tuple(reg.r3, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(8, 0xffffffff))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                    tuple(reg.r2, 0x000000ee),
                                    tuple(reg.r3, tiny_mem.ram_origin + 10)),
                      mem: make_mem(tuple(8, 0xffeeffff)))),
    test_case(0x68fb, 
              instr_16(op: opcode.ldr_imm_t1, rt: reg.r3, rn: reg.r7, imm: 12),
              tiny_vm(cpu: make_cpu(tuple(reg.r3, 0xff0000ff), 
                                    tuple(reg.r7, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(24, 0xaa0000ee))), 
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2), 
                                    tuple(reg.r3, 0xaa0000ee), 
                                    tuple(reg.r7, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(24, 0xaa0000ee)))),
    test_case(0x58fb, 
              instr_16(op: opcode.ldr_reg_t1, rt: reg.r3, rn: reg.r7, rm: reg.r3),
                tiny_vm(cpu: make_cpu(tuple(reg.r3, 12), 
                                      tuple(reg.r7, tiny_mem.ram_origin + 12)),
                        mem: make_mem(tuple(24, 0xffffffee))),
                tiny_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                      tuple(reg.r3, 0xffffffee),
                                      tuple(reg.r7, tiny_mem.ram_origin + 12)),
                        mem: make_mem(tuple(24, 0xffffffee)))),
    test_case(0x5cd3, 
              instr_16(op: opcode.ldrb_reg_t1, rt: reg.r3, rn: reg.r2, rm: reg.r3),
              tiny_vm(cpu: make_cpu(tuple(reg.r2, tiny_mem.ram_origin + 12), 
                                    tuple(reg.r3, 14)),
                      mem: make_mem(tuple(24, 0xffeeffff))),
              tiny_vm(cpu: make_cpu(tuple(reg.pc, 2),
                                    tuple(reg.r3, 0x000000ee),
                                    tuple(reg.r2, tiny_mem.ram_origin + 12)),
                      mem: make_mem(tuple(24, 0xffeeffff))))              
  ];

  foreach (t; tests) {
    record_tested_opcode(t.instr.op);
    execute_instr(t.instr, t.before);
    assert(
        t.before == t.expected,
        format("Failed for instruction 0x%08X:\n %s\n %s", t.instr_bytes, cpu_diff(t.before.cpu, t.expected.cpu), mem_diff(t.before.mem, t.expected.mem))
    );
  }
}

unittest {
    import std.stdio;
    import std.traits : EnumMembers;

    enum GREEN = "\x1b[32m";
    enum RED   = "\x1b[31m";
    enum RESET = "\x1b[0m";
    enum BLUE  = "\x1b[34m";

    int untested_count;
    int tested_count;
    foreach(op; EnumMembers!opcode) {
        if (!tested_opcodes.canFind(op)) {
          writeln(RED ~ "Missing test for opcode " ~ op.stringof ~ RESET);
          untested_count++;
        } else 
          tested_count++;
    }
    writeln(BLUE  ~ untested_count.to!string ~ " untested opcodes" ~ RESET);
    writeln(GREEN ~ tested_count.to!string   ~ " tested opcodes"   ~ RESET);
}





