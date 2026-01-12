import std.container;
import std.conv;

enum special_reg : ubyte {
	APSR = 			0b00000000,
	IAPSR =         0b00000001,
	EAPSR =			0b00000010,
	XPSR = 			0b00000011,
	IPSR = 			0b00000101,
	EPSR = 			0b00000110,
	IEPSR =			0b00000111,
	MSP =			0b00001000,
	PSP =   		0b00001001,
	PRIMASK = 	    0b00010000,
	BASEPRI = 		0b00010001,
	BASEPRI_MAX =	0b00010010,
	FAULTMASK =	    0b00010011,
	CONTROL =		0b00010100
}

enum exception {
	thread_mode,
	SVC_IRQn = 11,
	SysTick_IRQn = 15
}

enum condition : ubyte {
	cs = 0b0010,	// carry set
	eq = 0b0000,
	lt = 0b1011,
	gt = 0b1100,
	ge = 0b1010,
	le = 0b1101,
	mi = 0b0100,
	ne = 0b0001,
	pl = 0b0101,
	hi = 0b1000,
	ls = 0b1001,
	vs = 0b0110,
	vc = 0b0111,
	cc = 0b0011, 	// carry clear
	al = 0b1110,
	invalid = 0xff
}

condition get_negation(condition cond) {
	if (cond == condition.invalid) {
		return condition.invalid;
	}
	return cast(condition)(cond ^ 1);
}

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

// ==============
//  CORTEX M CPU
// ==============

struct cortex_m_cpu {

	// ------------------------------ General-Purpose Registers ----------------------------- 
	uint r0;
	uint r1;
	uint r2;
	uint r3;
	uint r4;
	uint r5;
	uint r6;
	uint r7;
	uint r8;
	uint r9;
	uint r10;
	uint r11;
	uint r12;

	uint sp;	// stack pointer
	uint lr;	// link register
	uint pc;	// program counter

	// ==============
	//  INCREMENT PC
	// ==============

	void increment_pc(int val) {
		pc += val;
	}
	// -------------------------------------------------------------------------------------- 

	// ------------------------------------ Stack Pointer ----------------------------------- 
	bool sp_sel;	// stack pointer select
	bool saved_sp_sel;
	uint msp;		// main stack pointer
	uint psp;		// process stack pointer

	// ========
	//  GET SP
	// ========

	uint get_sp() {
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

	int tick;
	
	uint get(reg r) {
		switch (r) {
			case reg.r0:
				return r0;
			case reg.r1:
				return r1;
			case reg.r2:
				return r2;
			case reg.r3:
				return r3;
			case reg.r4:
				return r4;
			case reg.r5: 
				return r5;
			case reg.r6:
				return r6;
			case reg.r7:
				return r7;
			case reg.r8: 
				return r8;
			case reg.r9:
				return r9;
			case reg.r10:
				return r10;
			case reg.r11:
				return r11;
			case reg.r12:
				return r12;
			case reg.pc:
				return pc;
			case reg.lr:
				return lr;
			case reg.sp:
				return get_sp();
			default:
				return r3;
		}
	}

	void set(reg r, int val) {
		switch (r) {
			case reg.r0:
				r0 = cast(uint)(val);
				return;
			case reg.r1:
				r1 = cast(uint)(val);
				return;
			case reg.r2:
				r2 = cast(uint)(val);
				return;
			case reg.r3:
				r3 = cast(uint)(val);
				return;
			case reg.r4:
				r4 = cast(uint)(val);
				return;
			case reg.r5: 
				r5 = cast(uint)(val);
				return;
			case reg.r6:
				r6 = cast(uint)(val);
				return;
			case reg.r7:
				r7 = cast(uint)(val);
				return;
			case reg.r8:
				r8 = cast(uint)(val);
				return;
			case reg.r9:
				r9 = cast(uint)(val);
				return;
			case reg.r10:
				r10 = cast(uint)(val);
				return;
			case reg.r11:
				r11 = cast(uint)(val);
				return;
			case reg.r12:
				r12 = cast(uint)(val);
				return;
			case reg.pc:
				pc = cast(uint)(val);
				return;
			case reg.lr:
				lr = cast(uint)(val);
				return;
			case reg.sp:
				set_sp(cast(uint)(val));
				return;
			default:
				return;
		}
	}
}