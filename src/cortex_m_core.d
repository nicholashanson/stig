import std.container;
import std.conv;
import std.format;
import std.traits : isIntegral;
import std.string : toUpper;

import thumb_2_misc_16;
import thumb_2_instrs;
import thumb_2_opcodes;
import cortex_m_scb;
import scb_defs;

enum IABR_BASE = 0xE000E300;
enum IPR_BASE  = 0xE000E400;
enum ISPR_BASE = 0xE000E200;

// ==========================
//  128-BIT UNSIGNED INTEGER
// ==========================

struct u128 {
    ulong low;
    ulong high;
}
// --------------------------------------------------------------------------------------
// ===========================
//  IS EXCEPTION RETURN VALUE
// ===========================

bool is_exc_ret_val(const uint val) {
	return ((val & 0xff00_0000) == 0xff00_0000);
}
// --------------------------------------------------------------------------------------

bool test_unsigned_neg(const uint v) {
	return (v & 0x8000_0000) != 0;
}
// --------------------------------------------------------------------------------------
// ===================
//  SPECIAL REGISTERS
// ===================

enum special_reg : ubyte {
	// Holds flags that can be written by application-level software, 
	// that is, by unprivileged software.
	APSR        = 0b00000000,
	// A composite of IPSR and APSR. 
	IAPSR       = 0b00000001,
	// A composite of EPSR and APSR.
	EAPSR       = 0b00000010,
	// The Program Status Register (PSR) is a 32-bit register that comprises three 
	// subregisters:
	//		- Application Program Status Register, APSR
	//		- Interrupt Program Status Register, IPSR
	//		- Execution Program Status Register, EPSR
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
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      Exception                                      * 
// ***************************************************************************************

// ===========
//  EXCEPTION
// ===========

enum string EXCEPTION = q{
	nmi 		 = -2,
	thread_mode  = 0,
	svc_irqn     = 11,
	pendsv_irqn  = 14,
	systick_irqn = 15,
};

enum string ARMv7_M_EXCEPTION = q{
	reset      = -3,
	hard_fault = -1,
};

enum string ARMv8_M_EXCEPTION = q{
	reset      			  = -4,
	hard_fault_secure     = -3,
	hard_fault_non_secure = -1,
};

mixin(() {
    string code = "enum exception : byte {\n";

    code ~= EXCEPTION;

    version (ARMv7_M) {
    	code ~= ARMv7_M_EXCEPTION;
    }

    version (ARMv8_M) {
    	code ~= ARMv8_M_EXCEPTION;
    }

    code ~= "}\n";

    return code;
}());   
// --------------------------------------------------------------------------------------
// hardware saved frame
reg[] hsf = [reg.r0, reg.r1, reg.r2, reg.r3, reg.r12, reg.lr, reg.pc /*, XPSR */];
// --------------------------------------------------------------------------------------
// ======================
//  DEACTIVATE EXCEPTION
// ======================

void
deactivate_exc
(vm_t)
(const uint i, ref vm_t vm) {
	const uint reg_n    = i / 32;
	const uint reg_addr = IABR_BASE + (reg_n * 4);
	// ExceptionActive[ReturningExceptionNumber] = ‘0’;
	uint       reg      = vm.peek_word(reg_addr);
	const uint shift_n  = i % 32;
	reg                ^= (1u << shift_n);
	vm.write_word(reg_addr, reg);
	// PRIMASK and BASEPRI unchanged on exception exit
	// if IPSR<8:0> != ‘000000010’ then
	if (vm.get_ipsr() != 0b10) 
		//	FAULTMASK<0> = ‘0’; 
		// clear FAULTMASK on any return except NMI
		vm.set_fault_mask(false);
	// return;
}
// --------------------------------------------------------------------------------------
// ======================
//  EXCEPTION IS PENDING
// ======================

bool
exc_is_pending
(vm_t)
(const uint i, ref vm_t vm) {
	const uint reg_n    = i / 32;
	const uint reg_addr = ISPR_BASE + (reg_n * 4);
	uint       reg      = vm.peek_word(reg_addr);
	const uint shift_n  = i % 32;
	return cast(bool)slice(reg, shift_n, 1);
}
// --------------------------------------------------------------------------------------
// ===========
//  POP STACK
// ===========

void 
pop_stack
(vm_t)
(uint frame_ptr, const uint exc_return, ref vm_t vm) {
	// if HaveFPExt() && EXC_RETURN<4> == ‘0’ then framesize = 0x68; forcealign = ‘1’;
	// else framesize = 0x20;
	const uint frame_size = 32;
	// forcealign = CCR.STKALIGN;
	// R[0] = MemA[frameptr,4];
	vm.set_reg(reg.r0,  vm.read_word(frame_ptr));
	// R[1] = MemA[frameptr+0x4,4];
	vm.set_reg(reg.r1,  vm.read_word(frame_ptr + 4));
	// R[2] = MemA[frameptr+0x8,4];
	vm.set_reg(reg.r2,  vm.read_word(frame_ptr + 8));
	// R[3] = MemA[frameptr+0xC,4];
	vm.set_reg(reg.r3,  vm.read_word(frame_ptr + 12));
	// R[12] = MemA[frameptr+0x10,4];
	vm.set_reg(reg.r12, vm.read_word(frame_ptr + 16));
	// LR = MemA[frameptr+0x14,4];
	vm.set_reg(reg.lr,  vm.read_word(frame_ptr + 20));
	// PC = MemA[frameptr+0x18,4]; // UNPREDICTABLE if the new PC not halfword aligned
	vm.set_reg(reg.pc,  vm.read_word(frame_ptr + 24));
	// psr = MemA[frameptr+0x1C,4];
	vm.set_xpsr(vm.read_word(frame_ptr + 28));
	// if HaveFPExt() then
	// if EXC_RETURN<4> == ‘0’ then
	// if FPCCR.LSPACT == ‘1’ then
	// FPCCR.LSPACT = ‘0’; // state in FP is still valid
	// else
	// CheckVFPEnabled();
	// for i = 0 to 15
	// S[i] = MemA[frameptr+0x20+(4*i),4];
	// FPSCR = MemA[frameptr+0x60,4];
	// CONTROL.FPCA = NOT(EXC_RETURN<4>);
	vm.set_fpca(cast(bool)slice(exc_return, 4, 1));
	// spmask = Zeros(29)((psr<9> AND forcealign):’00’;
	// case EXC_RETURN<3:0> of
	immutable exc_rtr_lb = slice(exc_return, 0, 4);
	switch (exc_rtr_lb) {
		// when ‘0001’ // returning to Handler
		case 0b0001:
			// SP_main = (SP_main + framesize) OR spmask;
			vm.set_msp(vm.get_msp() + frame_size);
			break;
		// when ‘1001’ // returning to Thread using Main stack
		case 0b1001:
			// SP_main = (SP_main + framesize) OR spmask;
			vm.set_msp(vm.get_msp() + frame_size);
			break;
		// when ‘1101’ // returning to Thread using Process stack
		case 0b1101:
			// SP_process = (SP_process + framesize) OR spmask;
			vm.set_psp(vm.get_psp() + frame_size);
			break;
		default:
			break;
	}
	// APSR<31:27> = psr<31:27>; // valid APSR bits loaded from memory
	// if HaveDSPExt() then
	// APSR<19:16> = psr<19:16>;
	// IPSR<8:0> = psr<8:0>; // valid IPSR bits loaded from memory
	// EPSR<26:24,15:10> = psr<26:24,15:10>; // valid EPSR bits loaded from memory
	// return;
}
// --------------------------------------------------------------------------------------
// ==================
//  EXCEPTION RETURN
// ==================

void 
exc_rtr
(vm_t)
(const uint exc_return, ref vm_t vm) {
    // ExceptionReturn(bits(28) EXC_RETURN)
	// assert CurrentMode == Mode_Handler;
	assert(vm.get_curr_exc() != exception.thread_mode,
		   "Trying to return from exception in thread mode");
	// if HaveFPExt() then
	// 		if !IsOnes(EXC_RETURN<27:5>) then UNPREDICTABLE;
	// else
	// 		if !IsOnes(EXC_RETURN<27:4>) then UNPREDICTABLE;
	assert(slice(exc_return, 5, 12) == 0xfff, 
		   format("Invalid exception return: %08X", exc_return));
	// integer ReturningExceptionNumber = UInt(IPSR<8:0>);
	const uint rtr_excn = vm.get_ipsr();
	// integer NestedActivation; // used for Handler => Thread check when value == 1
	// NestedActivation = ExceptionActiveBitCount(); // Number of active exceptions
	// if ExceptionActive[ReturningExceptionNumber] == ‘0’ then
	// DeActivate(ReturningExceptionNumber);
	// UFSR.INVPC = ‘1’;
	// LR = 0xF0000000 + EXC_RETURN;
	// ExceptionTaken(UsageFault); 
	// returning from an inactive handler
	// return;
	// else
	uint frame_ptr;
	// case EXC_RETURN<3:0> of
	immutable exc_rtr_lb = slice(exc_return, 0, 4);
	switch (exc_rtr_lb) {
		// when ‘0001’ 
		// return to Handler
		case 0b0001:
			// frameptr = SP_main;
			frame_ptr = vm.get_msp();
			// CurrentMode = Mode_Handler;
			// CONTROL.SPSEL = ‘0’;
			vm.set_sp_sel(false);
			break;
		// when ‘1001’ 
		// returning to Thread using Main stack
		case 0b1001:
			// if NestedActivation != 1 && CCR.NONBASETHRDENA == ‘0’ then
			// DeActivate(ReturningExceptionNumber);
			// UFSR.INVPC = ‘1’;
			// LR = 0xF0000000 + EXC_RETURN;
			// ExceptionTaken(UsageFault); 
			// return to Thread exception mismatch
			// return;
			// else
			// frameptr = SP_main;
			frame_ptr = vm.get_msp();
			// CurrentMode = Mode_Thread;
			vm.set_curr_exc(exception.thread_mode);
			// CONTROL.SPSEL = ‘0’;
			vm.set_sp_sel(false);
			break;
		// when ‘1101’ 
		// returning to Thread using Process stack
		case 0b1101:
			// if NestedActivation != 1 && CCR.NONBASETHRDENA == ‘0’ then
			// DeActivate(ReturningExceptionNumber);
			// UFSR.INVPC = ‘1’;
			// LR = 0xF0000000 + EXC_RETURN;
			// ExceptionTaken(UsageFault); 
			// return to Thread exception mismatch
			// return;
			// else
			// frameptr = SP_process;
			frame_ptr = vm.get_psp();
			// CurrentMode = Mode_Thread;
			vm.set_curr_exc(exception.thread_mode);
			// CONTROL.SPSEL = ‘1’;
			vm.set_sp_sel(true);
			break;
		// otherwise
		default:
			// DeActivate(ReturningExceptionNumber);
			// UFSR.INVPC = ‘1’;
			// LR = 0xF0000000 + EXC_RETURN;
			// ExceptionTaken(UsageFault); 
			// illegal EXC_RETURN
			// return;
			// DeActivate(ReturningExceptionNumber);
			assert(0);
			break;
	}
	// DeActivate(ReturningExceptionNumber);
	deactivate_exc(rtr_excn, vm);
	// PopStack(frameptr);
	pop_stack(frame_ptr, exc_return, vm);
	// if CurrentMode==Mode_Handler AND IPSR<8:0> == ‘000000000’ then
	// 		UFSR.INVPC = ‘1’;
	// 		PushStack(); 
	// 		to negate PopStack()
	// 		LR = 0xF0000000 + EXC_RETURN;
	// 		ExceptionTaken(UsageFault); 
	// 		return IPSR is inconsistent
	// 		return;
	// if CurrentMode==Mode_Thread AND IPSR<8:0> != ‘000000000’ then
	// 		UFSR.INVPC = ‘1’;
	// 		PushStack(); 
	// 		to negate PopStack()
	// 		LR = 0xF0000000 + EXC_RETURN;
	// 		ExceptionTaken(UsageFault); 
	// 		return IPSR is inconsistent
	// 		return;
}
// --------------------------------------------------------------------------------------
// ==============
//  GET IRQ ADDR
// ==============

uint
get_irq_addr
(vm_t)
(const exception irqn, ref vm_t vm) {
	immutable  vtor_raw     = vm.peek_word(0xE000_ED08);
	const uint vector_base  = vtor_raw & 0xFFFF_FF80;
	return vm.peek_word(vector_base + 4 * irqn);
}
// --------------------------------------------------------------------------------------
// ============
//  PUSH STACK
// ============

void 
push_stack
(vm_t)
(const uint frame_ptr, const uint return_addr, ref vm_t vm) {
	// MemA[frameptr,4] = R[0];
	vm.write_word(frame_ptr,      vm.get_reg(reg.r0));
	// MemA[frameptr+0x4,4] = R[1];
	vm.write_word(frame_ptr + 4,  vm.get_reg(reg.r1));
	// MemA[frameptr+0x8,4] = R[2];
	vm.write_word(frame_ptr + 8,  vm.get_reg(reg.r2));
	// MemA[frameptr+0xC,4] = R[3];
	vm.write_word(frame_ptr + 12, vm.get_reg(reg.r3));
	// MemA[frameptr+0x10,4] = R[12];
	vm.write_word(frame_ptr + 16, vm.get_reg(reg.r12));
	// MemA[frameptr+0x14,4] = LR;
	vm.write_word(frame_ptr + 20, vm.get_reg(reg.lr));
	// MemA[frameptr+0x18,4] = ReturnAddress();
	vm.write_word(frame_ptr + 24, return_addr);
	// MemA[frameptr+0x1C,4] = (xPSR<31:10>:frameptralign:xPSR<8:0>);
	vm.write_word(frame_ptr + 28, vm.get_xpsr());
}
// --------------------------------------------------------------------------------------
// =============
//  PUSH TO PSP
// =============

bool
push_to_psp
(vm_t)
(ref vm_t vm) {
	return vm.get_sp_sel() && (vm.get_curr_exc() == exception.thread_mode);
}
// --------------------------------------------------------------------------------------
// ===============
//  GET FRAME PTR
// ===============

uint 
get_frame_ptr
(vm_t)
(ref vm_t vm) {
	// if CONTROL.SPSEL == ‘1’ AND CurrentMode == Mode_Thread then
	if (push_to_psp(vm)) 
		// frameptr = SP_process;
		return vm.get_psp();
	else
		// frameptr = SP_main;
		return vm.get_msp();
}
// --------------------------------------------------------------------------------------
// ============================
//  GET EXCEPTION RETURN VALUE
// ============================

uint
get_exc_rtr_val
(vm_t)
(ref vm_t vm) {
	// if Mode==Handler
	if (vm.get_curr_exc() != exception.thread_mode)
		// LR = Ones(27):NOT(CONTROL.FPCA):’0001’;
		if (vm.get_fpca()) 
			return 0xFFFF_FFE1;
		else 
			return 0xFFFF_FFF1;
	else
		// LR = Ones(27):NOT(CONTROL.FPCA):’1’:CONTROL.SPSEL:’01’;
		if (vm.get_fpca()) 
			if (vm.get_sp_sel())
				return 0xFFFF_FFED;   
			else 
				return 0xFFFF_FFE9;
		else 
			if (vm.get_sp_sel())
				return 0xFFFF_FFFD;
			else 
				return 0xFFFF_FFF9;
}
// --------------------------------------------------------------------------------------
// =========================
//  SET EXCEPTION AS ACTIVE
// =========================

void
set_exc_as_active
(vm_t)
(const exception exc, ref vm_t vm) {
	const uint i        = cast(uint)exc;
	const uint reg_n    = i / 32;
	const uint reg_addr = IABR_BASE + (reg_n * 4);
	uint       reg      = vm.peek_word(reg_addr);
	const uint shift_n  = i % 32;
	reg                |= (1u << shift_n);
	vm.write_word(reg_addr, reg);
}
// --------------------------------------------------------------------------------------
// =============================
//  GET SYSTEM HANDLER PRIORITY
// =============================

uint get_sys_hdlr_pri(const exception exc) {
	assert(exc > 3 && exc < 16);
	uint shpr_base;
    uint byte_index;
    if (exc < 8) {
        shpr_base  = SHPR1;              
        byte_index = exc - 4;          
    } else if (exc < 12) {
        shpr_base  = SHPR2;
        byte_index = exc - 8;
    } else {
        shpr_base  = SHPR3;
        byte_index = exc - 12;
    }
    uint word = scb_ctrl.read_word(shpr_base);      
    return (word >> (byte_index * 8)) & 0xff; 
}
// --------------------------------------------------------------------------------------
// =================
//  ENTER EXCEPTION
// =================

void 
enter_exec
(vm_t)
(const exception exc, ref vm_t vm) {
	const uint frame_size  = 32;
	uint       frame_ptr   = get_frame_ptr(vm);
	frame_ptr 			  -= frame_size;
	// if CONTROL.SPSEL == ‘1’ AND CurrentMode == Mode_Thread then
	if (push_to_psp(vm)) 
		// frameptralign = SP_process<2> AND forcealign;
		// SP_process = (SP_process - framesize) AND spmask;
		// frameptr = SP_process;
		vm.set_psp(frame_ptr);
	// else
	else
		// frameptralign = SP_main<2> AND forcealign;
		// SP_main = (SP_main - framesize) AND spmask;
		// frameptr = SP_main;
		vm.set_msp(frame_ptr);
	const uint return_addr = exc == exception.svc_irqn ? vm.get_pc() + 2 : vm.get_pc(); 
	push_stack(frame_ptr, return_addr, vm);
	vm.set_reg(reg.lr, get_exc_rtr_val(vm));
	// tmp = MemA[VectorTable+4*ExceptionNumber,4];
	// PC = tmp AND 0xFFFFFFFE;
	vm.set_reg(reg.pc, get_irq_addr(exc, vm));
	// IPSR<8:0> = ExceptionNumber // ExceptionNumber set in IPSR
	vm.set_ipsr(cast(uint)exc);
	// CONTROL.FPCA = ‘1’; // Floating-point extension only
	vm.set_fpca(true);
	// EPSR.T = tbit; // T-bit set from vector
	// EPSR.IT<7:0> = 0x0; // IT/ICI bits cleared
	// //* PRIMASK, FAULTMASK, BASEPRI unchanged on exception entry*//
	vm.set_curr_exc(exc);
	// ExceptionActive[ExceptionNumber]= ‘1’;
	set_exc_as_active(exc, vm);
	// CONTROL.SPSEL = ‘0’; // current Stack is Main, CONTROL.nPRIV unchanged
	vm.set_sp_sel(false);
	//* CONTROL.nPRIV unchanged *//
	if (exc == exception.pendsv_irqn)
		vm.write_word(ICSR, (1u << PENDSVCLR));
	if (exc == exception.systick_irqn)
		vm.write_word(ICSR, (1u << PENDSTCLR));
}
// --------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                      Condition                                      * 
// ***************************************************************************************

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
// --------------------------------------------------------------------------------------
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
// --------------------------------------------------------------------------------------
// ==============
//  GET NEGATION
// ==============

condition get_negation(condition cond) {
	if (cond == condition.invalid)
		return condition.invalid;
	return cast(condition)(cond ^ 1);
}
// --------------------------------------------------------------------------------------
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
// =====
//  REG
// =====
enum reg : ubyte {
	r0, r1, r2, r3,  r4,  r5, r6, 
	r7, r8, r9, r10, r11, r12,
	sp,   	// stack pointer
	lr,		// link register
	pc,		// program counter
	// 32-bit floating-point registers
	s0,   s1,  s2,  s3,  s4,  s5,  s6,  s7,  s8,  s9, s10, s11, s12, s13, s14, s15, 
	s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31,
	// 64-bit views of floating-point registers
	d0,   d1,  d2,  d3,  d4,  d5,  d6,  d7,  d8,  d9, d10, d11, d12, d13, d14, d15, 
	// 128-bit views of floating-point registers
	q0,   q1,  q2,  q3,  q4,  q5,  q6,  q7,
	none
}
// --------------------------------------------------------------------------------------
// =====
//  XYZ
// =====
enum xyz {
	t, e, tt, et, te, ee,
	ttt, ett, tet, eet, tte,
	ete, tee, eee,
	none
}
// --------------------------------------------------------------------------------------
// ======
//  FLAG
// ======
enum flag {
  	z, c, n, v,
  	ge0, ge1, ge2, ge3,
  	none
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
	const uint reg_n    = i / 32;
	const uint reg_addr = IABR_BASE + (reg_n * 4);
	immutable  reg      = vm.peek_word(reg_addr);
	const uint shift_n  = i % 32;
	return cast(bool)slice(reg, shift_n, 1);
}
// --------------------------------------------------------------------------------------
// ========================
//  Get Exception Priority
// ========================

uint 
get_exception_priority
(vm_t)
(const uint i, ref vm_t vm) {
	const uint reg_n    =  i / 4;
	const uint reg_addr = IPR_BASE + (reg_n * 4);
	immutable  reg      = vm.peek_word(reg_addr);
	const uint shift_n  = (i % 4) * 8;
	return slice(reg, shift_n, 8);
}
// --------------------------------------------------------------------------------------
// ===============================
//  Get Highest Pending Exception
// ===============================

exception 
get_highest_pending_ext_exc
(vm_t)
(ref vm_t vm) {
	immutable exec_pri  = get_execution_priority(vm); 
    exception candidate = exception.thread_mode;     
    int lowest_irqn     = 512;                           
    foreach (uint i; 0 .. 512) {
        if (exc_is_pending(i, vm)) {
            auto pri = get_exception_priority(i, vm);
            if (pri == cast(uint)exec_pri && i < lowest_irqn) {
                lowest_irqn = i;
                candidate = cast(exception)i;
            }
        }
    }
    return candidate;
}  

// --------------------------------------------------------------------------------------
bool is_system_pending
(vm_t)
(const exception exc, ref vm_t vm) {
	switch (exc) {
		case exception.systick_irqn:
			return scb_ctrl.st_pending;
        case exception.pendsv_irqn:
            return scb_ctrl.psv_pending;
		default:
			return false;
	}
}
// --------------------------------------------------------------------------------------
// ===============================
//  GET NEXT EXECUTABLE EXCPETION
// ===============================

exception 
get_next_executable_exception
(vm_t)
(ref vm_t vm) {
    int curr_exec_pri = get_execution_priority(vm); 
    exception candidate = exception.thread_mode;
    int highest_pri = 256; 
    foreach (uint exc; 4 .. 16) {
        if (is_system_pending(cast(exception)exc, vm)) {
            int pri = cast(int)get_sys_hdlr_pri(cast(exception)exc);
            if (pri < highest_pri && pri < curr_exec_pri) {
                highest_pri = pri;
                candidate = cast(exception)exc;
            }
        }
    }
    foreach (uint i; 0 .. 512) {
        if (exc_is_pending(i, vm)) {
            int pri = cast(int)get_exception_priority(i, vm);
            if (pri < highest_pri && pri < curr_exec_pri) {
                highest_pri = pri;
                candidate = cast(exception)(i + 16);
            }
        }
    }
    return candidate;
}
// --------------------------------------------------------------------------------------
// ========================
//  Get Execution Priority
// ========================
// integer ExecutionPriority()

int 
get_execution_priority
(vm_t)
(ref vm_t vm) {
	int priority;
	// highestpri = 256; 
	// priority of Thread mode with no active exceptions
	// the value is PriorityMax + 1 = 256
	// (configurable priority maximum bit field is 8 bits)
	int highest_pri = 256;
	// boostedpri = 256; 
	// priority influence of BASEPRI, PRIMASK and FAULTMASK
	int boosted_pri = 256;

	// subgroupshift = UInt(BITS(3) AIRCR.PRIGROUP)
	immutable  aicr 		 = vm.peek_word(0xE000ED0C);
	const uint sub_grp_shift = slice(aicr, 8, 3);
	// groupvalue = ‘000000010’ LSL groupshift 
	// used by priority grouping
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
// ==========
//  PROPERTY
// ==========

mixin template property(string name) {
    enum code =
        "auto get_" ~ name ~ "() const pure nothrow @nogc {\n" ~
        "    return this." ~ name ~ ";\n" ~
        "}\n" ~
        "\n" ~
        "void set_" ~ name ~ "(typeof(this." ~ name ~ ") v) pure nothrow @nogc {\n" ~
        "    this." ~ name ~ " = v;\n" ~
        "}\n";

    mixin(code);
}
// --------------------------------------------------------------------------------------

// ==============
//  CORTEX M CPU
// ==============

// =======================================
//  Indicates instruction execution state
// =======================================

alias it_state_t = ubyte;

struct instr_exec_state {
	uint     		fetch_addr;
	it_state_t 		  it_state;
	// L, T166IND, BTI, LOBranchInfoValid
	ubyte                 bits;
	uint            loop_count;
	bool        reset_ltp_size;
}

mixin template define_bit_helpers(string reg, bits...) 
if (bits.length % 2 == 0) 
{
	enum string reg_name = reg.toUpper();
    mixin(() {
        string code = "";
        
        static foreach (i; 0 .. bits.length / 2) {{
            enum string bit_name = bits[i * 2];
            enum uint bit_pos    = bits[i * 2 + 1];
            enum uint mask       = 1u << bit_pos;

            code ~= format(
                "pragma(inline, true) bool %s_%s_SET(vm_t)(ref vm_t vm) pure nothrow @nogc {\n" ~
                "    return (vm.get_%s() & 0x%X) != 0;\n" ~
                "}\n",
                reg_name, bit_name, reg, mask
            );

            code ~= format(
                "pragma(inline, true) bool %s_%s_CLEAR(vm_t)(ref vm_t vm) pure nothrow @nogc {\n" ~
                "    return (vm.get_%s() & 0x%X) == 0;\n" ~
                "}\n",
                reg_name, bit_name, reg, mask
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm) pure nothrow @nogc {\n" ~
                "    auto val = vm.get_%s();\n" ~
                "    vm.set_%s(cast(typeof(val))(val | 0x%X));\n" ~
                "}\n",
                reg_name, bit_name, reg, reg, mask
            );

            code ~= format(
                "pragma(inline, true) void CLEAR_%s_%s(vm_t)(ref vm_t vm) pure nothrow @nogc {\n" ~
                "    auto val = vm.get_%s();\n" ~
                "    vm.set_%s(cast(typeof(val))(val & ~0x%X));\n" ~
                "}\n",
                reg_name, bit_name, reg, reg, mask
            );
        }}
        
        return code;
    }());
}

mixin template define_bit_helpers_scb(alias reg, bits...) 
if (bits.length % 2 == 0) 
{
    mixin(() {
        string code = "";

        enum string reg_name    = __traits(identifier, reg);
        
        static foreach (i; 0 .. bits.length / 2) {{
            enum string bit_name = bits[i * 2];
            enum uint bit_pos    = bits[i * 2 + 1];
            enum uint mask       = 1u << bit_pos;

            code ~= format(
                "pragma(inline, true) bool %s_%s_SET(vm_t)(ref vm_t vm) {\n" ~
                "    return (vm.read_word(cast(size_t)%d) & 0x%X) != 0;\n" ~
                "}\n",
                reg_name, bit_name, reg, mask
            );

            code ~= format(
                "pragma(inline, true) bool %s_%s_CLEAR(vm_t)(ref vm_t vm) {\n" ~
                "    return (vm.read_word(cast(size_t)%d) & 0x%X) == 0;\n" ~
                "}\n",
                reg_name, bit_name, reg, mask
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm) {\n" ~
                "    auto val = vm.read_word(%d);\n" ~
                "    vm.write_word(cast(size_t)%d, cast(typeof(val))(val | 0x%X));\n" ~
                "}\n",
                reg_name, bit_name, reg, reg, mask
            );

            code ~= format(
                "pragma(inline, true) void CLEAR_%s_%s(vm_t)(ref vm_t vm) {\n" ~
                "    auto val = vm.read_word(%d);\n" ~
                "    vm.write_word(cast(size_t)%d, cast(typeof(val))(val & ~0x%X));\n" ~
                "}\n",
                reg_name, bit_name, reg, reg, mask
            );
        }}
        
        return code;
    }());
}

version (ARMv8_M) {
// 66-bit read/write register.
mixin define_bit_helpers!("lo_branch_info_low",  "VALID", 0);
mixin define_bit_helpers!("lo_branch_info_high", "BF", 0);
mixin define_bit_helpers!("lo_branch_info_high_2", "LF", 0, "T16IND", 1);
}
mixin define_bit_helpers!("fpscr", "AHP", 26, "DN", 25, "FZ", 24, "FZ16", 19, "IDC", 7, "IXC", 4, "UFC", 3, "OFC", 2, "DZC", 1, "IOC", 0);
mixin define_bit_helpers!("ccr", "TRD", 20, "LOB", 19, "BP", 18, "IC", 17, "DC", 16, "STKOFHFNMIGN", 10, "BFHFNMIGN", 8, "DIV_0_TRP", 4, "UNALIGN_TRP", 3, "USERSETMPEND", 1);

mixin define_bit_helpers_scb!(FP_CTRL, "CTRL_KEY", 1, "ENABLE", 0);
mixin define_bit_helpers_scb!(DFSR, "PMU", 5, "EXTERNAL", 4, "VCATCH", 3, "DWTTRAP", 2, "BKPT", 1, "HALTED", 0);
mixin define_bitfield_helpers_scb!(DHCSR, "DBGKEY", 16, 16,  "S_RESTART_ST", 26, 1, "S_RESET_ST", 25, 1, "S_RETIRE_ST", 24, 1, "S_FPD", 23, 1, "S_SUIDE", 22, 1, 
										  "S_NSUIDE", 21, 1, "S_SDE", 20, 1, "S_LOCKUP", 19, 1, "S_SLEEP", 18, 1, "S_HALT", 17, 1, "S_REGRDY", 16, 1, "C_MASKINTS", 3, 1, 
										  "C_STEP", 2, 1, "C_HALT", 1, 1, "C_DEBUGEN", 0, 1);
// DEMCR, Debug Exception and Monitor Control Register
// Manages vector catch behavior and DebugMonitor handling when debugging.
mixin define_bitfield_helpers_scb!(DEMCR, "TRCENA", 24, 1, "MONPRKEY", 23, 1, "UMON_EN", 21, 16,  "SDME", 20, 1, "MON_REQ", 19, 1, "MON_STEP", 18, 1, "MON_PEND", 17, 1, "MON_EN", 16, 1, 
										  "VC_SFERR", 11, 1, "VC_HARDERR", 10, 1, "VC_INTERR", 9, 1, "VC_BUSERR", 8, 1, "VC_STATERR", 7, 1, "VC_CHKERR", 6, 1, "VC_NOCPERR", 5, 1, 
										  "VC_MMERR", 4, 1, "VC_CORERESET", 0, 1);
mixin define_bitfield_helpers_scb!(UFSR, "DIVBYZERO", 9, 1, "UNALIGNED", 8, 1, "STKOF", 4, 1, "NOCP", 3, 1, "INVPC", 2, 1, "INVSTATE", 1, 1, "UNDEFINSTR", 0, 1);
mixin define_bitfield_helpers_scb!(DWT_CTL, "NUMCOMP", 28, 4, "NOTRCPKT", 27, 1, "NOEXTTRIG", 26, 1, "NOCYCCNT", 25, 1,  "NOPRFCNT", 24, 1, "CYCDISS", 23, 1, "CYCEVTENA", 22, 1, "FOLDEVTENA", 21, 1, "LSUEVTENA", 20, 1, 
										    "SLEEPEVTENA", 19, 1, "EXCEVTENA", 18, 1, "CPIEVTENA", 17, 1, "EXCTRCENA", 16, 1, "PCSAMPLENA", 12, 1, "SYNCTAP", 10, 2, "CYCTAP", 9, 1, 
										    "POSTINIT", 5, 4, "POSTPRESET", 4, 1, "CYCCNTENA", 0, 1);
// Non-secure Access Control Register
mixin define_bitfield_helpers_scb!(NSACR, "CP11", 11, 1, "CP10", 10, 1, "CP7", 7, 1, "CP6", 6, 1, "CP5", 5, 1, "CP4", 4, 1, 
										  "CP3", 3, 1, "CP2", 2, 1, "CP1", 1, 1, "CP0", 0, 1);
version (ARMv7_M) {
mixin define_bitfield_helpers_scb!(FPCCR, "ASPEN", 31, 1,  "LSPEN", 30, 1, "LSPENS", 29, 1, "CLRONRET", 28, 1, "CLRONRETS", 27, 1, "TS", 26, 1, 
										  "UFRDY", 10, 1, "SPLIMVIOL", 9, 1, "MONRDY", 8, 1, "SFRDY", 7, 1, "BFRDY", 6, 1, "MMRDY", 5, 1, "HFRDY", 4, 1, 
										  "THREAD", 3, 1, "S", 2, 1, "USER", 1, 1, "LSPACT", 0, 1);
mixin define_bitfield_helpers_scb!(CPACR, "CP11", 22, 2, "CP10", 20, 2, "CP7", 14, 2, "CP6", 12, 2, 
									      "CP5", 10, 2,  "CP4", 8, 2,   "CP3", 6, 2,  "CP2", 4, 2, "CP1", 2, 2, "CP0", 0, 2);
}
version (ARMv8_M) {
mixin define_bitfield_helpers_scb_secure!(FPCCR, "ASPEN", 31, 1,  "LSPEN", 30, 1, "LSPENS", 29, 1, "CLRONRET", 28, 1, "CLRONRETS", 27, 1, "TS", 26, 1, 
										  		 "UFRDY", 10, 1, "SPLIMVIOL", 9, 1, "MONRDY", 8, 1, "SFRDY", 7, 1, "BFRDY", 6, 1, "MMRDY", 5, 1, "HFRDY", 4, 1, 
										  		 "THREAD", 3, 1, "S", 2, 1, "USER", 1, 1, "LSPACT", 0, 1);
mixin define_bitfield_helpers_scb!(FPCCR_S, "ASPEN", 31, 1,  "LSPEN", 30, 1, "LSPENS", 29, 1, "CLRONRET", 28, 1, "CLRONRETS", 27, 1, "TS", 26, 1, 
										    "UFRDY", 10, 1, "SPLIMVIOL", 9, 1, "MONRDY", 8, 1, "SFRDY", 7, 1, "BFRDY", 6, 1, "MMRDY", 5, 1, "HFRDY", 4, 1, 
										    "THREAD", 3, 1, "S", 2, 1, "USER", 1, 1, "LSPACT", 0, 1);
mixin define_bitfield_helpers_scb!(FPCCR_NS, "ASPEN", 31, 1,  "LSPEN", 30, 1, "LSPENS", 29, 1, "CLRONRET", 28, 1, "CLRONRETS", 27, 1, "TS", 26, 1, 
										     "UFRDY", 10, 1, "SPLIMVIOL", 9, 1, "MONRDY", 8, 1, "SFRDY", 7, 1, "BFRDY", 6, 1, "MMRDY", 5, 1, "HFRDY", 4, 1, 
										     "THREAD", 3, 1, "S", 2, 1, "USER", 1, 1, "LSPACT", 0, 1);		
mixin define_bitfield_helpers_scb_secure!(CPACR, "CP11", 22, 2, "CP10", 20, 2, "CP7", 14, 2, "CP6", 12, 2, 
									      		 "CP5", 10, 2,  "CP4", 8, 2,   "CP3", 6, 2,  "CP2", 4, 2, "CP1", 2, 2, "CP0", 0, 2);
mixin define_bitfield_helpers_scb!(CPACR_S, "CP11", 22, 2, "CP10", 20, 2, "CP7", 14, 2, "CP6", 12, 2, 
									        "CP5", 10, 2,  "CP4", 8, 2,   "CP3", 6, 2,  "CP2", 4, 2, "CP1", 2, 2, "CP0", 0, 2);
mixin define_bitfield_helpers_scb!(CPACR_NS, "CP11", 22, 2, "CP10", 20, 2, "CP7", 14, 2, "CP6", 12, 2, 
									         "CP5", 10, 2,  "CP4", 8, 2,   "CP3", 6, 2,  "CP2", 4, 2, "CP1", 2, 2, "CP0", 0, 2);
// SFSR, Secure Fault Status Register
mixin define_bitfield_helpers_scb!(SFSR, "LSERR", 7, 1, "SFARVALID", 6, 1, "LSPERR", 5, 1, "INVTRAN", 4, 1, 
										 "AUVIOL", 3, 1, "INVER", 2, 1, "INVIS", 1, 1, "INVEP", 0, 1);
mixin define_bitfield_helpers_scb_secure!(CPPWR, "SUS11", 23, 1, "SU11", 22, 1, "SUS10", 21, 1, "SU10", 20, 1, "SUS7", 15, 1, "SU7", 14, 1, "SUS6", 13, 1, "SU6", 12, 1, 
										         "SUS5", 11, 1, "SU5", 10, 1, "SUS4", 9, 1, "SU4", 8, 1, "SUS3", 7, 1, "SU3", 6, 1, "SUS2", 5, 1, "SU2", 4, 1,  "SUS1", 3, 1, 
										         "SU1", 2, 1, "SUS0", 1, 1, "SU0", 0, 1);
mixin define_bitfield_helpers_scb!(CPPWR_S, "SUS11", 23, 1, "SU11", 22, 1, "SUS10", 21, 1, "SU10", 20, 1, "SUS7", 15, 1, "SU7", 14, 1, "SUS6", 13, 1, "SU6", 12, 1, 
										    "SUS5", 11, 1, "SU5", 10, 1, "SUS4", 9, 1, "SU4", 8, 1, "SUS3", 7, 1, "SU3", 6, 1, "SUS2", 5, 1, "SU2", 4, 1,  "SUS1", 3, 1, 
										    "SU1", 2, 1, "SUS0", 1, 1, "SU0", 0, 1);
mixin define_bitfield_helpers_scb!(CPPWR_NS, "SUS11", 23, 1, "SU11", 22, 1, "SUS10", 21, 1, "SU10", 20, 1, "SUS7", 15, 1, "SU7", 14, 1, "SUS6", 13, 1, "SU6", 12, 1, 
										     "SUS5", 11, 1, "SU5", 10, 1, "SUS4", 9, 1, "SU4", 8, 1, "SUS3", 7, 1, "SU3", 6, 1, "SUS2", 5, 1, "SU2", 4, 1,  "SUS1", 3, 1, 
										     "SU1", 2, 1, "SUS0", 1, 1, "SU0", 0, 1);
}

mixin(() {
    string code;

    static foreach (n; 0 .. 126)
    {
        code ~= format(
            "mixin define_bitfield_helpers_scb!(FP_COMP%d, \"BP_ADDR\", 1, 31, \"BE\", 0, 1);\n",
            n
        );
    }

    static foreach (n; 0 .. 14)
    {
        code ~= format(
            "mixin define_bitfield_helpers_scb!(DWT_FUNCTION%d, \"ID\", 27, 5, \"MATCHED\", 24, 1, \"ACTION\", 4, 2, \"MATCH\", 0, 4);\n",
            n
        );
    }

    return code;
}());

mixin template define_bitfield_helpers(string reg, fields...)
if (fields.length % 3 == 0)
{
    mixin(() {
        string code = "";
        enum string reg_name_lc   = reg;
        enum string reg_name_up   = reg.toUpper();

        static foreach (i; 0 .. fields.length / 3) {{
            enum string field_name = fields[i * 3];
            enum uint start_pos    = fields[i * 3 + 1];
            enum uint width        = fields[i * 3 + 2];
            
            enum uint field_mask   = (1u << width) - 1u;
            enum uint reg_mask     = field_mask << start_pos;

            code ~= format(
                "pragma(inline, true) auto GET_%s_%s(vm_t)(ref vm_t vm) pure nothrow @nogc {\n" ~
                "    return (vm.get_%s() >> %d) & 0x%X;\n" ~
                "}\n",
                reg_name_up, field_name, reg_name_lc, start_pos, field_mask
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm, uint val) pure nothrow @nogc {\n" ~
                "    auto current = vm.get_%s();\n" ~
                "    auto cleared = current & ~0x%Xu;\n" ~
                "    auto new_val = cleared | ((cast(typeof(current))val & 0x%X) << %d);\n" ~
                "    vm.set_%s(cast(typeof(current))new_val);\n" ~
                "}\n",
                reg_name_up, field_name, reg_name_lc, reg_mask, field_mask, start_pos, reg_name_lc
            );
        }}

        return code;
    }());
}

mixin template define_bitfield_helpers_alt(string reg, fields...)
if (fields.length % 3 == 0)
{
    mixin(() {
        string code = "";
        enum string reg_name_lc   = reg;
        enum string reg_name_up   = reg.toUpper();

        static foreach (i; 0 .. fields.length / 3) {{
            enum string field_name = fields[i * 3];
            enum uint start_pos    = fields[i * 3 + 1];
            enum uint width        = fields[i * 3 + 2];
            
            enum uint field_mask   = (1u << width) - 1u;
            enum uint reg_mask     = field_mask << start_pos;

            code ~= format(
                "pragma(inline, true) auto GET_%s_%s(vm_t)(ref vm_t vm, uint val) {\n" ~
                "    return (val >> %d) & 0x%X;\n" ~
                "}\n",
                reg_name_up, field_name, start_pos, field_mask
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm, ref uint traget, uint val) {\n" ~
                "    auto cleared = target & ~0x%Xu;\n" ~
                "    auto new_val = cleared | ((cast(typeof(current))val & 0x%X) << %d);\n" ~
                "    target = new_val;\n" ~
                "}\n",
                reg_name_up, field_name, reg_mask, field_mask, start_pos
            );
        }}

        return code;
    }());
}


mixin template define_bitfield_helpers_scb(alias reg, fields...)
if (fields.length % 3 == 0)
{
    mixin(() {
        string code = "";

        enum string reg_name = __traits(identifier, reg);

        static foreach (i; 0 .. fields.length / 3) {{
            enum string field_name = fields[i * 3];
            enum uint start_pos    = fields[i * 3 + 1];
            enum uint width        = fields[i * 3 + 2];
            
            enum uint field_mask   = (1u << width) - 1u;
            enum uint reg_mask     = field_mask << start_pos;

            code ~= format(
                "pragma(inline, true) auto GET_%s_%s(vm_t)(ref vm_t vm) {\n" ~
                "    return (vm.read_word(cast(size_t)%d) >> %d) & 0x%X;\n" ~
                "}\n",
                reg_name, field_name, reg, start_pos, field_mask
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm, uint val) {\n" ~
                "    auto current = vm.read_word(cast(size_t)%d);\n" ~
                "    auto cleared = current & ~0x%Xu;\n" ~
                "    auto new_val = cleared | ((cast(typeof(current))val & 0x%X) << %d);\n" ~
                "    vm.write_word(cast(size_t)%d, cast(typeof(current))new_val);\n" ~
                "}\n",
                reg_name, field_name, reg, reg_mask, field_mask, start_pos, reg
            );
        }}

        return code;
    }());
}

mixin template define_bitfield_helpers_scb_alt(alias reg, fields...)
if (fields.length % 3 == 0)
{
    mixin(() {
        string code = "";

        enum string reg_name = __traits(identifier, reg);

        static foreach (i; 0 .. fields.length / 3) {{
            enum string field_name = fields[i * 3];
            enum uint start_pos    = fields[i * 3 + 1];
            enum uint width        = fields[i * 3 + 2];
            
            enum uint field_mask   = (1u << width) - 1u;
            enum uint reg_mask     = field_mask << start_pos;

            code ~= format(
                "pragma(inline, true) auto GET_%s_%s(vm_t)(ref vm_t vm, uint val) {\n" ~
                "    return (val >> %d) & 0x%X;\n" ~
                "}\n",
                reg_name, field_name, start_pos, field_mask
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm, ref uint traget, uint val) {\n" ~
                "    auto cleared = target & ~0x%Xu;\n" ~
                "    auto new_val = cleared | ((cast(typeof(current))val & 0x%X) << %d);\n" ~
                "    target = new_val;\n" ~
                "}\n",
                reg_name, field_name, reg_mask, field_mask, start_pos
            );
        }}

        return code;
    }());
}

mixin template define_bitfield_helpers_scb_secure(alias reg, fields...)
if (fields.length % 3 == 0)
{
    mixin(() {
        string code = "";

        enum string reg_name = __traits(identifier, reg);

        static foreach (i; 0 .. fields.length / 3) {{
            enum string field_name = fields[i * 3];
            enum uint start_pos    = fields[i * 3 + 1];
            enum uint width        = fields[i * 3 + 2];
            
            enum uint field_mask   = (1u << width) - 1u;
            enum uint reg_mask     = field_mask << start_pos;

            code ~= format(
                "pragma(inline, true) auto GET_%s_%s(vm_t)(ref vm_t vm) {\n" ~
                "    if (vm.get_curr_state == vm.security_state.secure)\n" ~
                "	 	return GET_%s_S_%s(vm);\n" ~
                "    else\n" ~
                "    	return GET_%s_NS_%s(vm);\n" ~
                "}\n",
                reg_name, field_name, reg_name, field_name, reg_name, field_name
            );

            code ~= format(
                "pragma(inline, true) void SET_%s_%s(vm_t)(ref vm_t vm, uint val) {\n" ~
                "    if (vm.get_curr_state == vm.security_state.secure)\n" ~
                "    	return SET_%s_S_%s(vm);\n" ~
                "    else\n" ~
                "    	return SET_%s_NS_%s(vm);\n" ~
                "}\n",
                reg_name, field_name, reg_name, field_name, reg_name, field_name
            );
        }}

        return code;
    }());
}

mixin define_bitfield_helpers!("fpscr", "RMode", 22, 2, "LTPSIZE", 16, 3);
mixin define_bitfield_helpers_alt!("fpscr", "RMode", 22, 2);
mixin define_bitfield_helpers_scb!(FP_CTRL, "REV", 28, 4, "NUM_CODE_HIGH", 12, 3, "NUM_LIT", 8, 4, "NUM_CODE_LOW", 4, 4);
version (ARMv8_M) {
mixin define_bitfield_helpers!("epsr", "ECI_HIGH_HIGH", 25, 2, "ICI_HIGH", 25, 2, "IT_HIGH", 25, 2, "T", 24, 1, "ECI_HIGH", 12, 4, 
	                                   "ECI_LOW", 10, 2,       "ICI_LOW", 10, 6,  "IT_LOW", 10, 6);
uint 
GET_EPSR_IT
(vm_t)
(ref vm_t vm) {
	return (GET_EPSR_IT_HIGH(vm) << 6) | GET_EPSR_IT_LOW(vm);
}
uint 
GET_EPSR_ICI
(vm_t)
(ref vm_t vm) {
	return (GET_EPSR_ICI_HIGH(vm) << 6) | GET_EPSR_ICI_LOW(vm);
}
uint
GET_EPSR_ECI
(vm_t)
(ref vm_t vm) {
	return (GET_EPSR_ECI_HIGH_HIGH(vm) << 6) | (GET_EPSR_ECI_HIGH(vm) << 2) | GET_EPSR_ECI_LOW(vm);
}
// VPR, Vector Predication Status and Control Register
// Holds the per element predication flags.
mixin define_bitfield_helpers!("vpr", "P0", 0, 16, "MASK01", 16, 4, "MASK23", 20, 4, "RES0", 24, 8);
mixin define_bitfield_helpers!("lo_branch_info_low",  "JUMP_ADDR", 1, 31);
mixin define_bitfield_helpers!("lo_branch_info_high", "END_ADDR",  1, 31);
}

struct cortex_m_cpu {

	instr_exec_state curr_instr_exec_state;

	instr_exec_state get_curr_instr_exec_state() {
		return curr_instr_exec_state;
	}

	void set_curr_instr_exec_state(const instr_exec_state state) {
		curr_instr_exec_state = state;
	}
	// ------------------------------ General-Purpose Registers ----------------------------- 
	uint[16] core_registers;
	uint[32] fp_registers;

	// ====================
	//  GET CORE REGISTERS
	// ====================

	uint[16] get_core_registers() const {
		return core_registers;
	}
	// --------------------------------------------------------------------------------------
	
	// =========
	//  GET REG
	// =========

	uint get_reg(const reg r) const {
		assert((r >= reg.r0) && (r <= reg.pc));
		if (r == reg.sp) 
			return get_sp();
		if (r == reg.pc)
			return get_pc() + 4;
		return core_registers[r];
	}

	// ===========
	//  GET REG S
	// ===========

	uint get_reg_s(reg r) const {
		assert((r > reg.pc) && (r <= reg.s31));
		size_t i = r - reg.s0;
		return fp_registers[i];
	}

	// ===========
	//  GET REG D
	// ===========

	ulong get_reg_d(reg r) const {
		assert((r > reg.s31) && (r <= reg.d15));
		size_t i = reg.s0 + (r - reg.d0) * 2;
		ulong res = (ulong(get_reg_s(cast(reg)i)) << 32) | ulong(get_reg_s(cast(reg)(i + 1)));
		return res;
	}

	// ===========
	//  GET REG Q
	// ===========

	u128 get_reg_q(reg r) const {
		assert((r > reg.d15) && (r <= reg.q7));
		size_t i = reg.d0 + (r - reg.q0) * 2;
		ulong high = get_reg_d(cast(reg)i);
		ulong low  = get_reg_d(cast(reg)(i + 1));
		return u128(high: high, low: low);
	}
	// --------------------------------------------------------------------------------------

	// =========
	//  SET REG
	// =========

	void set_reg(const reg r, const uint val) {
		if (r == reg.sp)		
			set_sp(val);
		else {
			core_registers[r] = val;
			if ((r == reg.pc) && !is_exc_ret_val(val))
				clear_thumb_bit();
		}
	}

	// ===========
	//  SET REG S
	// ===========

	void set_reg_s(const reg r, const uint val) {
		assert((r > reg.s0) && (r <= reg.s31));
		size_t i = r - reg.s0;
		fp_registers[i] = val;
	}

	// ===========
	//  SET REG D
	// ===========

	void set_reg_d(reg r, const ulong val) {
		assert((r > reg.d0) && (r <= reg.d15));
		size_t i = reg.s0 + (r - reg.d0) * 2;
		set_reg_s(cast(reg)i,       slice(val, 0,  32));
		set_reg_s(cast(reg)(i + 1), slice(val, 31, 32));
	}

	// ===========
	//  SET REG Q
	// ===========

	void set_reg_q(const reg r, const u128 val) {
		assert((r > reg.d15) && (r <= reg.q7));
		size_t i = reg.d0 + (r - reg.q0) * 2;
		set_reg_d(cast(reg)i,       val.high);
		set_reg_d(cast(reg)(i + 1), val.low);
	}

	// ==============
	//  INCREMENT PC
	// ==============

	void increment_pc(int val) {
		core_registers[reg.pc] += val;
	}

	// ========
	//  GET PC
	// ========

	uint get_pc() const {
		return core_registers[reg.pc];
	}

	// =================
	//  CLEAR THUMB BIT
	// =================

	void clear_thumb_bit() {
		core_registers[reg.pc] &= ~1;
	}

	// ==========
	//  ALIGN PC
	// ==========

	void align_pc() {
		core_registers[reg.pc] &= ~0x3;
	}
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
	mixin property!"sp_sel";
	uint msp;		// main stack pointer
	mixin property!"msp";
	uint psp;		// process stack pointer
	mixin property!"psp";

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
	// ---------------------------------------- Flags ---------------------------------------
	mixin property!"c";
	mixin property!"v";

	// --------------------------------------------------------------------------------------
	// =======
	//  GET N
	// =======

	bool get_n() const {
		return n;
	}

	// =======
	//  SET N
	// =======

	void set_n(const uint v) {
		n = test_unsigned_neg(v);
	}

	void set_n(const int v) {
		n = (v < 0);
	}

	void set_n(const bool v) {
		n = v;
	}
	// --------------------------------------------------------------------------------------
	// =======
	//  GET Z
	// =======

	bool get_z() const {
		return z;
	}

	// =======
	//  SET Z
	// =======

	void set_z(t)(t v) if (isIntegral!t) {
    	z = (v == 0);
	}

	void set_z(const bool v) {
		z = v;
	}
	// --------------------------------------------------------------------------------------
	// ===========
	//  SET FLAGS
	// ===========

	void set_flag(flag f, bool i) {
		final switch (f) {
			case flag.z   : z   = i; break;
			case flag.n   : n   = i; break;
			case flag.v   : v   = i; break;
			case flag.c   : c   = i; break;
			case flag.ge0 : ge0 = i; break;
			case flag.ge1 : ge1 = i; break;
			case flag.ge2 : ge2 = i; break;
			case flag.ge3 : ge3 = i; break;
			case flag.none:          break;
		}
	}
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
	mixin property!"ge0";
	bool ge1;
	mixin property!"ge1";
	bool ge2;
	mixin property!"ge2";
	bool ge3;
	mixin property!"ge3";

	// ==========
	//  GET APSR
	// ==========
pure nothrow @nogc {
	uint get_apsr() const {
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
}

	// IPSR
	exception curr_exc;
	mixin property!"curr_exc";

	// ==========
	//  GET IPSR
	// ==========
pure nothrow @nogc {
	uint get_ipsr() const {
		uint isr;
    	if (curr_exc == exception.thread_mode)
        	isr = 0;
    	else
        	isr = cast(uint)curr_exc;
        return (isr & 0x1ff); 
    }

    // ==========
	//  SET IPSR
	// ==========

    void set_ipsr(const uint ipsr) {
    	immutable val = slice(ipsr, 0, 8);
    	curr_exc      = cast(exception)val;
    }
}

    // ==========
	//  GET EPSR
	// ==========
pure nothrow @nogc {
version (ARMv7_M) {
	uint get_epsr() const {
    	return (1u << 24);
	}
}
version (ARMv8_M) {
	uint epsr;
	mixin property!"epsr";
}

	// ==========
	//  GET XPSR
	// ==========

	uint get_xpsr() const {
    	return get_apsr() | get_ipsr() | get_epsr();
	}

	// ==========
	//  SET XSPR
	// ==========

	void set_xpsr(const uint xpsr) {
    	set_apsr(xpsr);
    	set_ipsr(xpsr);
    }
}

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
pure nothrow @nogc {
	// reset clears the control register to zero
	uint get_control_reg() {
		uint control;

		if (npriv ) control |= (1u     );
	    if (sp_sel) control |= (1u << 1);
	    if (fpca  ) control |= (1u << 2);

	    return control;
	}
}

	bool npriv;		// defines the execution privilege in Thread mode
	mixin property!"npriv";
	bool fpca;		// defines whether the FP extension is active in the current context
	mixin property!"fpca";
	// --------------------------- Special-Purpose Mask Registers ---------------------------
	// ================
	//  GET FAULT MASK
	// ================
pure nothrow @nogc {
	uint get_fault_mask() const {
		return fault_mask ? 1 : 0;
	}

	// ================
	//  SET FAULT MASK
	// ================

	void set_fault_mask(const bool v) {
		fault_mask = v;
	}

	// ==============
	//  GET PRI MASK
	// ==============

	uint get_pri_mask() const {
		return pri_mask ? 1 : 0;
	}
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
	mixin property!"basepri";
	// --------------------------------------------------------------------------------------

	// =======
	//  FPCSR
	// =======
	uint fpcsr;
	mixin property!"fpcsr";

	// =======
	//  FPSCR
	// =======
	uint fpscr;
	mixin property!"fpscr";

	// =======
	//  FPCCR
	// =======
	uint fpccr;
	mixin property!"fpccr";

	version (ARMv8_M) {
		uint beat_id;
		mixin property!"beat_id";

		uint ccr;
		mixin property!"ccr";

		// Indicates a change in instruction fetch address due to branch type operations
		bool pc_changed;
		mixin property!"pc_changed";

		bool pending_ret_op;
		mixin property!"pending_ret_op";

		uint lo_branch_info_low;
		uint lo_branch_info_high;
		uint lo_branch_info_high_2;
		mixin property!"lo_branch_info_low";
		mixin property!"lo_branch_info_high";
		mixin property!"lo_branch_info_high_2";

		uint this_instr_addr;
		mixin property!"this_instr_addr";
		uint next_instr_addr;
		mixin property!"next_instr_addr";

		uint vpr;
		mixin property!"vpr";

		uint inst_id;
		mixin property!"inst_id";
	}
}
