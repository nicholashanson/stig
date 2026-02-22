import std.container;
import std.conv;
import std.format;
import std.traits : isIntegral;

import memory_sections;
import thumb_2_misc_16;
import thumb_2_instrs;
import thumb_2_opcodes;

bool test_unsigned_neg(const uint v) {
	return (v & 0x8000_0000) != 0;
}

enum special_reg : ubyte {
	APSR        = 0b00000000,
	IAPSR       = 0b00000001,
	EAPSR       = 0b00000010,
	XPSR        = 0b00000011,
	IPSR        = 0b00000101,
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
	systick_irqn = 15
}

reg[] hardware_saved_frame = [reg.r0, reg.r1, reg.r2, reg.r3, reg.r12, reg.lr, reg.pc /*, XPSR */];

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
	auto pop_instr = instr_16(op: opcode.pop_t1, reg_list: hardware_saved_frame);
	execute_pop_t1(pop_instr, vm);
	vm.set_xpsr(vm.pop());
    vm.clear_thumb_bit();
    if (return_to_thread)
        cpu.current_exception = exception.thread_mode;
    if (return_to_thread)
        cpu.npriv = false;
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
		auto push_instr = instr_16(op: opcode.push_t1, reg_list: hardware_saved_frame);
		execute_push_t1(push_instr, vm);
	}
	vm.set_current_exception(exception.systick_irqn);
	vm.set_npriv(false);
	vm.set_reg(reg.lr, vm.get_sp_sel() ? 0xffff_fffd : 0xffff_fff9); 
	vm.set_sp_sel(false);
	uint vtor_raw = vm.read_word(0xE000_ED08);
	uint vector_base = vtor_raw & 0xFFFF_FF80;
	uint systick_addr = vector_base + 4 * exception.systick_irqn;
	immutable pc = vm.read_word(systick_addr);
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
	invalid = 0xff
}

// ==================
//  CONDITION IS MET
// ==================

bool condition_is_met(condition cond, ref cortex_m_cpu cpu) {
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
  	v
}

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
		else 
			core_registers[r] = val;
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
		core_registers[reg.pc] &= 0x3;
	}

	uint get_tick() const {
		return tick;
	}

	void inc_tick() {
		tick++;
	}
	// -------------------------------------------------------------------------------------- 
	uint tick;
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
	
	// ---------------------------------------- xPSR ---------------------------------------- 
	bool n;
	bool z;
	bool c;
	bool v;
	bool ge0;
	bool ge1;
	bool ge2;
	bool ge3;
	exception current_exception;

	// ---------------------------------------- Flags ---------------------------------------
	bool get_c() const {
		return c;
	}

	void set_c(const bool v) {
		c = v;
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

	void set_z(t)(t v) if (isIntegral!t) {
    	z = (v == 0);
	}

	void set_flag(flag f, bool i) {
		final switch (f) {
			case flag.z: z = i; break;
			case flag.n: n = i; break;
			case flag.v: v = i; break;
			case flag.c: c = i; break;
		}
	}
	// -------------------------------------------------------------------------------------- 

	// ==========
	//  GET XPSR
	// ==========

	uint get_xpsr() {
    	uint xpsr = 0;

	    if (n) xpsr |= (1u << 31);
	    if (z) xpsr |= (1u << 30);
	    if (c) xpsr |= (1u << 29);
	    if (v) xpsr |= (1u << 28);

    	xpsr |= (1u << 24);

    	uint isr;
    	if (current_exception == exception.thread_mode)
        	isr = 0;
    	else
        	isr = cast(uint)current_exception;

    	xpsr |= (isr & 0x1ff); 

    	return xpsr;
	}

	// ==========
	//  SET XSPR
	// ==========

	void set_xpsr(uint xpsr) {
    	n = (xpsr & (1u << 31)) != 0;
    	z = (xpsr & (1u << 30)) != 0;
    	c = (xpsr & (1u << 29)) != 0;
    	v = (xpsr & (1u << 28)) != 0;
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
	// software must use an ISB barrier instruction to ensure a write to the CONTROL register
	// takes effect before the next insturction is executed

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
		return pri_mask ? 1 : 0;
	}

	// ==============
	//  GET PRI MASK
	// ==============

	uint get_pri_mask() {
		return fault_mask ? 1 : 0;
	}

	// ==============
	//  GET BASE PRI
	// ==============

	uint get_base_pri() {
		return basepri;
	}

	bool fault_mask;
	bool pri_mask;
	ubyte basepri;
	// --------------------------------------------------------------------------------------
}

