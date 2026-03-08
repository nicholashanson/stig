import std.container;
import std.conv;
import std.format;
import std.traits : isIntegral;

import thumb_2_misc_16;
import thumb_2_instrs;
import thumb_2_opcodes;

bool test_unsigned_neg(const uint v) {
	return (v & 0x8000_0000) != 0;
}

enum special_reg : ubyte {
	// Holds flags that can be written by application-level software, 
	// that is, by unprivileged software.
	APSR        = 0b00000000,
	// A composite of IPSR and APSR. 
	IAPSR       = 0b00000001,
	// A composite of EPSR and APSR.
	EAPSR       = 0b00000010,
	XPSR        = 0b00000011,
	// The processor writes to the IPSR on exception entry and exit. 
	// Software can use an MRS instruction, to read the IPSR, but 
	// the processor ignores writes to the IPSR by an MSR instruction. 
	// The IPSR Exception Number field is defined as follows:
	// 		- in Thread mode, the value is 0
	//		- in Handler mode, holds the exception number of the 
	//        currently-executing exception.
	IPSR        = 0b00000101,
	// The EPSR contains the T bit, that is set to 1 to indicate that 
	// the processor executes Thumb instructions, and an overlaid ICI 
	// or IT field that supports interrupt-continue load/store 
	// instructions and the IT instruction.
	EPSR        = 0b00000110,
	IEPSR       = 0b00000111,
	MSP 		= 0b00001000,
	PSP         = 0b00001001,
	PRIMASK     = 0b00010000,
	BASEPRI 	= 0b00010001,
	BASEPRI_MAX = 0b00010010,
	FAULTMASK   = 0b00010011,
	CONTROL     = 0b00010100
}

// ------------------------------------- Exception -------------------------------------- 

// ===========
//  EXECUTION
// ===========

enum exception {
	thread_mode,
	svc_irqn = 11,
	pendsv_irqn = 14,
	systick_irqn = 15
}

// hrdware saved frame
reg[] hsf = [reg.r0, reg.r1, reg.r2, reg.r3, reg.r12, reg.lr, reg.pc /*, XPSR */];

// ==================
//  EXCEPTION RETURN
// ==================

void 
exception_return
(vm_t)
(ref vm_t vm, const uint exc_return) {
    bool return_to_thread = (exc_return & (1 << 3)) != 0;
    bool use_psp 		  = (exc_return & (1 << 2)) != 0;
    vm.set_sp_sel(use_psp);
	auto pop_instr = instr_16(op: opcode.pop_t1, reg_list: hsf);
	execute_pop_t1(pop_instr, vm);
	vm.set_xpsr(vm.pop());
    if (return_to_thread)
        vm.set_current_exception(exception.thread_mode);
    if (return_to_thread)
        vm.set_npriv(false);
}

// ==================
//  EXECUTE SYS TICK
// ==================

void 
execute_sys_tick
(vm_t)
(ref vm_t vm) {
	if (vm.get_current_exception() == exception.thread_mode) {
		vm.push(vm.get_xpsr());
		auto push_instr = instr_16(op: opcode.push_t1, reg_list: hsf);
		execute_push_t1(push_instr, vm);
	}
	vm.set_current_exception(exception.systick_irqn);
	vm.set_npriv(false);
	vm.set_reg(reg.lr, vm.get_sp_sel() ? 0xffff_fffd : 0xffff_fff9); 
	vm.set_sp_sel(false);
	const uint vtor_raw     = vm.read_word(0xe000_ed08);
	const uint vector_base  = vtor_raw & 0xffff_ff80;
	const uint systick_addr = vector_base + 4 * exception.systick_irqn;
	immutable pc            = vm.read_word(systick_addr);
	vm.set_reg(reg.pc, pc);
	vm.align_pc();
}

// ================
//  EXECUTE PENDSV
// ================

void 
execute_pendsv
(vm_t)
(ref vm_t vm) {
	if (vm.get_current_exception() == exception.thread_mode) {
		vm.push(vm.get_xpsr());
		auto push_instr = instr_16(op: opcode.push_t1, reg_list: hsf);
		execute_push_t1(push_instr, vm);
	}
	vm.set_current_exception(exception.pendsv_irqn);
	vm.set_npriv(false);
	vm.set_reg(reg.lr, vm.get_sp_sel() ? 0xffff_fffd : 0xffff_fff9); 
	vm.set_sp_sel(false);
	const uint vtor_raw     = vm.read_word(0xe000_ed08);
	const uint vector_base  = vtor_raw & 0xffff_ff80;
	const uint pendsv_addr  = vector_base + 4 * exception.pendsv_irqn;
	immutable pc            = vm.read_word(pendsv_addr);
	vm.flip_bit(0xe000_ed04, 28);
	vm.set_reg(reg.pc, pc);
	vm.align_pc();
}
// --------------------------------------------------------------------------------------

// ------------------------------------- Condition --------------------------------------

enum condition : ubyte {
	cs		= 0b0010,			// carry set
	eq		= 0b0000,			// equal
	lt		= 0b1011,			// less-than
	gt		= 0b1100,			// greater-than
	ge		= 0b1010,			// greater-than or equal-to
	le		= 0b1101,			// less-than or equal-to
	mi		= 0b0100,	
	ne		= 0b0001,			// not equal
	pl		= 0b0101,
	hi		= 0b1000,
	ls		= 0b1001,
	vs		= 0b0110,
	vc		= 0b0111,
	cc		= 0b0011, 			// carry clear
	al		= 0b1110,
	invalid = 0xff,
	none    = 0xff
}

// ==================
//  CONDITION IS MET
// ==================

bool condition_is_met(condition cond, const ref cortex_m_cpu cpu) {
	final switch (cond) {
		case condition.eq: return cpu.z == 1;
		case condition.ne: return cpu.z == 0;
		case condition.cc: return cpu.c == 0;
		case condition.cs: return cpu.c == 1;
		case condition.ge: return cpu.n == cpu.v;
		case condition.mi: return cpu.n == 1;
		case condition.pl: return cpu.n == 0;
		case condition.hi: return cpu.c == 1 && cpu.z == 0;
		case condition.ls: return (cpu.c == 0) || (cpu.z == 1);
		case condition.vs: return cpu.v == 1;
        case condition.vc: return cpu.v == 0;
        case condition.lt: return cpu.n != cpu.v;
		case condition.gt: return cpu.z == 0 && cpu.n == cpu.v;
		case condition.le: return cpu.z == 1 || cpu.n != cpu.v;
		case condition.al: return true;
		case condition.invalid: assert(false, "Invalid condition");
	}
}

// ==============
//  GET NEGATION
// ==============

condition get_negation(condition cond) {
	if (cond == condition.invalid) {
		return condition.invalid;
	}
	return cast(condition)(cond ^ 1);
}

// =========
//  GET XYZ
// =========

xyz get_xyz(ubyte first_cond_mask) {
	ubyte first_cond = cast(ubyte)((first_cond_mask >> 4) & 0xf);
	ubyte mask = cast(ubyte)(first_cond_mask & 0xf);
	if (mask == 0b0001) {
		return xyz.none;
	}
	ubyte first_cond_0 = cast(ubyte)(first_cond & 0b1);
	auto bit0 = first_cond_0 ? 1 : 0;
	if (mask == ((bit0 << 3) | 0b100)) {
		return xyz.t;
	}
	if (mask == (((bit0 ^ 1) << 3) | 0b100)) {
		return xyz.e;
	}
	if (mask == ((bit0 << 3) | (bit0 << 2) | 0b10)) {
		return xyz.tt;
	}
	if (mask == (((bit0 ^ 1) << 3) | (bit0 << 2) | 0b10)) {
		return xyz.et;
	}
	if (mask == ((bit0 << 3) | !(bit0 << 2) | 0b10)) {
		return xyz.te;
	}
	if (mask == (((bit0 ^ 1) << 3) | ((bit0 ^ 1) << 2) | 0b10)) {
		return xyz.ee;
	}
	if (mask == ((bit0 << 3) | (bit0 << 2) | (bit0 << 1) | 0b1)) {
		return xyz.ttt;
	}
	if (mask == (((bit0 ^ 1) << 3) | (bit0 << 2) | (bit0 << 1) | 0b1)) {
		return xyz.ett;
	}
	if (mask == ((bit0 << 3) | ((bit0 ^ 1) << 2) | (bit0 << 1) | 0b1)) {
		return xyz.tet;
	}
	if (mask == (((bit0 ^ 1) << 3) | ((bit0 ^ 1) << 2) | (bit0 << 1) | 0b1)) {
		return xyz.eet;
	}
	if (mask == ((bit0 << 3) | (bit0 << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.tte;
	}
	if (mask == (((bit0 ^ 1) << 3) | (bit0 << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.ete;
	}
	if (mask == ((bit0 << 3) | ((bit0 ^ 1) << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.tee;
	}
	if (mask == (((bit0 ^ 1) << 3) | ((bit0 ^ 1) << 2) | ((bit0 ^ 1) << 1) | 0b1)) {
		return xyz.eee;
	}
	return xyz.none;
}
// --------------------------------------------------------------------------------------

enum reg : ubyte {
	r0,
	r1,
	r2,
	r3,
	r4,
	r5,
	r6,
	r7,
	r8,
	r9,
	r10,
	r11,
	r12,
	sp,   	// stack pointer
	lr,		// link register
	pc,		// program counter
	none
}

enum xyz {
	none,
	t,
	e,
	tt,
	et,
	te,
	ee,
	ttt,
	ett,
	tet,
	eet,
	tte,
	ete,
	tee,
	eee
}

enum flag {
  	z, 
  	c, 
  	n,
  	v,
  	ge0,
  	ge1,
  	ge2, 
  	ge3
}



// ***************************************************************************************
// *                                 Execution Priority                                  * 
// ***************************************************************************************

// =====================
//  Exception Is Active
// =====================

bool 
exception_is_active
(vm_t)
(const uint i, ref vm_t vm) {
	// IABR: 0xE000E300-0xE000E37C
	const uint base_reg = 0xE000E300; 
	const uint reg_n    = i / 32;
	const uint reg_addr = base_reg + (reg_n * 4);
	immutable  reg      = vm.read_word(reg_addr);
	const uint shift_n  = i % 32;
	return cast(bool)slice(reg, shift_n, 1);
}

// ========================
//  Get Exception Priority
// ========================

uint 
get_exception_priority
(vm_t)
(const uint i, ref vm_t vm) {
	// IPR: 0xE000E400-0xE000E7EC
	const uint base_reg = 0xE000E400;
	const uint reg_n    =  i / 4;
	const uint reg_addr = base_reg + (reg_n * 4);
	immutable  reg      = vm.read_word(reg_addr);
	const uint shift_n  = (i % 4) * 4;
	return slice(reg, shift_n, 4);
}

// ========================
//  Get Execution Priority
// ========================
// integer ExecutionPriority()

int 
get_execution_priority
(vm_t)
(ref vm_t vm) {
	int priority;
	// highestpri = 256; // priority of Thread mode with no active exceptions
	//					 // the value is PriorityMax + 1 = 256
	//					 // (configurable priority maximum bit field is 8 bits)
	int highest_pri = 256;
	// boostedpri = 256; // priority influence of BASEPRI, PRIMASK and FAULTMASK
	int boosted_pri = 256;

	// subgroupshift = UInt(BITS(3) AIRCR.PRIGROUP)
	immutable  aicr 		 = vm.read_word(0xE000ED0C);
	const uint sub_grp_shift = slice(aicr, 8, 3);
	// groupvalue = ‘000000010’ LSL groupshift // used by priority grouping
	const uint grp_val       = shift(0b10, shift_type.lsl, sub_grp_shift, false);

	// for (i=2, i<512, i=i+1) ; IPSR values of the exception handlers
	for (int i = 2; i < 512; ++i) {
		// if ExceptionActive[i] == ‘1’ then
		if (exception_is_active(i, vm)) {
			immutable exc_pri = get_exception_priority(i, vm);
			// if ExceptionPriority[i] < highestpri then
			if (exc_pri < highest_pri) {
				// highestpri = ExceptionPriority[i];
				highest_pri = exc_pri;
				// include the PRIGROUP effect
				// subgroupvalue = highestpri MOD groupvalue
				const uint sub_grp_val = highest_pri % grp_val;
				// highestpri = highestpri - subgroupvalue
				highest_pri -= sub_grp_val;	
			}
		}
	}

	immutable basepri = vm.get_basepri();
	// if Uint(BASEPRI<7:0>) != 0 then
	if (basepri != 0) {
			// boostedpri = Uint(BASEPRI<7:0>);
			boosted_pri = basepri;
			// include the PRIGROUP effect
			// subgroupvalue = boostedpri MOD groupvalue
			const uint sub_grp_val = boosted_pri % grp_val;
 			// boostedpri = boostedpri - subgroupvalue
 			boosted_pri -= sub_grp_val;
 	}
 	immutable pri_mask   = cast(bool)vm.get_pri_mask();
	// if PRIMASK<0> == ‘1’ then
	if (pri_mask) {
		// boostedpri = 0;
		boosted_pri = 0;
	}
	immutable fault_mask = cast(bool)vm.get_fault_mask();
	// if FAULTMASK<0> == ‘1’ then
	if (fault_mask) {
		// boostedpri = -1;
		boosted_pri = -1;
	}
	// if boostedpri < highestpri then
	if (boosted_pri < highest_pri) {
		// priority = boostedpri;
		priority = boosted_pri;
	} else {
		// priority = highestpri;
		priority = highest_pri;
	}
	// return (priority);
	return priority;
}
// --------------------------------------------------------------------------------------

// ==============
//  CORTEX M CPU
// ==============

struct cortex_m_cpu {

	// ------------------------------ General-Purpose Registers ----------------------------- 
	uint[16] core_registers;

	// =========
	//  GET REG
	// =========

	uint get_reg(const reg r) const {
		if (r == reg.sp) 
			return get_sp();
		return core_registers[r];
	}

	// =========
	//  SET REG
	// =========

	void set_reg(const reg r, const uint val) {
		if (r == reg.sp)		
			set_sp(val);
		else {
			core_registers[r] = val;
			if (r == reg.pc)
				clear_thumb_bit();
		}
	}

	// ==============
	//  INCREMENT PC
	// ==============

	void increment_pc(int val) {
		core_registers[reg.pc] += val;
	}

	uint get_pc() const {
		return core_registers[reg.pc];
	}

	void clear_thumb_bit() {
		core_registers[reg.pc] &= ~1;
	}

	void align_pc() {
		core_registers[reg.pc] &= ~0x3;
	}
	// -------------------------------------------------------------------------------------- 

	// ---------------------------------------- Tick ---------------------------------------- 
	uint tick;

	uint get_tick() const {
		return tick;
	}

	void inc_tick() {
		tick++;
	}
	// ------------------------------------ Stack Pointer ----------------------------------- 
	bool sp_sel;	// stack pointer select
	uint msp;		// main stack pointer
	uint psp;		// process stack pointer

	// ========
	//  GET SP
	// ========

	uint get_sp() const {
	    return sp_sel ? psp : msp;
	}

	// ========
	//  SET SP
	// ========

	void set_sp(uint val) {
	    if (sp_sel)
	        psp = val;
	    else
	        msp = val;
	}
	// -------------------------------------------------------------------------------------- 
	
	// ---------------------------------------- Flags ---------------------------------------
	bool get_c() const {
		return c;
	}

	void set_c(const bool v) {
		c = v;
	}

	bool get_v() const {
		return v;
	}

	void set_v(const bool v_) {
		v = v_;
	}

	void set_n(const uint v) {
		n = test_unsigned_neg(v);
	}

	void set_n(const int v) {
		n = (v < 0);
	}

	bool get_n() const {
		return n;
	}

	void set_z(t)(t v) if (isIntegral!t) {
    	z = (v == 0);
	}

	bool get_z() const {
		return z;
	}

	void set_flag(flag f, bool i) {
		final switch (f) {
			case flag.z  : z   = i; break;
			case flag.n  : n   = i; break;
			case flag.v  : v   = i; break;
			case flag.c  : c   = i; break;
			case flag.ge0: ge0 = i; break;
			case flag.ge1: ge1 = i; break;
			case flag.ge2: ge2 = i; break;
			case flag.ge3: ge3 = i; break;
		}
	}
	// -------------------------------------------------------------------------------------- 

	// ---------------------------------------- xPSR ---------------------------------------- 
	// The Program Status Register (PSR) is a 32-bit register that comprises three 
	// subregisters:
	//		- Application Program Status Register, APSR
	//		- Interrupt Program Status Register, IPSR
	//		- Execution Program Status Register, EPSR

	// APSR
	bool n;
	bool z;
	bool c;
	bool v;
	bool q;
	bool ge0;
	bool ge1;
	bool ge2;
	bool ge3;

	// ==========
	//  GET APSR
	// ==========

	uint get_apsr() {
		uint apsr = 0;
		if (n)   apsr |= (1u << 31);
	    if (z)   apsr |= (1u << 30);
	    if (c)   apsr |= (1u << 29);
	    if (v)   apsr |= (1u << 28);
	    if (q)   apsr |= (1u << 27);
	    if (ge3) apsr |= (1u << 19);
	    if (ge2) apsr |= (1u << 18);
	    if (ge1) apsr |= (1u << 17);
	    if (ge0) apsr |= (1u << 16);
	    return apsr;
	}

	// ==========
	//  SET APSR
	// ==========

	void set_apsr(const uint apsr) {
		n   = (apsr & (1u << 31)) != 0;
    	z   = (apsr & (1u << 30)) != 0;
    	c   = (apsr & (1u << 29)) != 0;
    	v   = (apsr & (1u << 28)) != 0;
    	q   = (apsr & (1u << 27)) != 0;
    	ge3 = (apsr & (1u << 19)) != 0;
    	ge2 = (apsr & (1u << 18)) != 0;
    	ge1 = (apsr & (1u << 17)) != 0;
    	ge0 = (apsr & (1u << 16)) != 0;
    }

	// IPSR
	exception current_exception;

	// ==========
	//  GET IPSR
	// ==========

	uint get_ipsr() {
		uint isr;
    	if (current_exception == exception.thread_mode)
        	isr = 0;
    	else
        	isr = cast(uint)current_exception;
        return (isr & 0x1ff); 
    }

    // ==========
	//  GET EPSR
	// ==========

	uint get_epsr() {
    	return (1u << 24);
	}

	// ==========
	//  GET XPSR
	// ==========

	uint get_xpsr() {
    	return get_apsr() | get_ipsr() | get_epsr();
	}

	// ==========
	//  SET XSPR
	// ==========

	void set_xpsr(const uint xpsr) {
    	set_apsr(xpsr);
    }
	// --------------------------------------------------------------------------------------

	// --------------------------------------- FPSCR ----------------------------------------
	void set_fpscr(const uint val) {
		fpscr = val;
	}

	uint fpscr;
	// --------------------------------------------------------------------------------------

	// -------------------------------------- IT Block -------------------------------------- 
	xyz it_block;
	Array!condition it_block_stack;

	// =============
	//  IN IT BLOCK
	// =============

	bool in_it_block() {
		return !it_block_stack.empty;
	}

	// =====================
	//  INIT IT BLOCK STACK
	// =====================

	void init_it_block_stack(condition cond) {
		if (it_block == xyz.none) {
			it_block_stack.insertBack(cond); 
			return;
		}
		string s = it_block.to!string;
		size_t len = s.length;
		if (len > 0) {
			for (size_t i = s.length; i-- > 0; ) {
			    char c = s[i];
			    if (c == 't') it_block_stack.insertBack(cond);
			    else if (c == 'e') it_block_stack.insertBack(get_negation(cond));
			}
		}
	    it_block_stack.insertBack(cond); 
	}
	// --------------------------------------------------------------------------------------

	// -------------------------------------- Control ---------------------------------------
	// The special-purpose CONTROL register is a 2-bit or 3-bit register defined as follows:
	//		- nPRIV, bit[0] Defines the execution privilege in Thread mode.
	//		- SPSEL, bit[1] Defines the stack to be used.
	//		- FPCA, bit[2], if the processor includes the FP extension.

	// Software must use an ISB barrier instruction to ensure a write to the CONTROL register
	// takes effect before the next insturction is executed.

	// On an exception entry or exception return, the processor updates the SPSEL bit and, 
	// if it implements the FP extension, the FPCA bit. 

	// =================
	//  GET CONTROL REG
	// =================

	// reset clears the control register to zero
	uint get_control_reg() {
		uint control;

		if (npriv ) control |= (1u     );
	    if (sp_sel) control |= (1u << 1);
	    if (fpca  ) control |= (1u << 2);

	    return control;
	}

	bool npriv;		// defines the execution privilege in Thread mode
	bool fpca;		// defines whether the FP extension is active in the current context
	// --------------------------------------------------------------------------------------

	// --------------------------- Special-Purpose Mask Registers ---------------------------
	
	// ================
	//  GET FAULT MASK
	// ================

	uint get_fault_mask() {
		return fault_mask ? 1 : 0;
	}

	// ==============
	//  GET PRI MASK
	// ==============

	uint get_pri_mask() {
		return pri_mask ? 1 : 0;
	}

	// ==============
	//  GET BASE PRI
	// ==============

	uint get_base_pri() {
		return basepri;
	}

	// The fault mask, a 1-bit register. Setting FAULTMASK to 1 raises the execution 
	// priority to -1, the priority of HardFault. Only privileged software executing at a 
	// priority below -1 set FAULTMASK to 1. This means HardFault and NMI handlers cannot 
	// set FAULTMASK to 1. Returning from any exception except NMI clears FAULTMASK to 0.
	bool fault_mask;
	// The exception mask register, a 1-bit register. Setting PRIMASK to 1 raises the 
	// execution priority to 0.
	bool pri_mask;
	// The base priority mask, an 8-bit register. BASEPRI changes the priority level 
	// required for exception preemption. It has an effect only when BASEPRI has a lower 
	// value than the unmasked priority level of the currently executing software.
	ubyte basepri;
	// --------------------------------------------------------------------------------------
}


