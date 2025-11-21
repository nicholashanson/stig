import std.algorithm : all, canFind;
import std.conv : to, ConvException;
import std.exception;
import std.string : indexOf, replace, split, strip, stripLeft;
import std.traits;
import std.variant : Algebraic;
import std.format : format;

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
}

struct imm {
	int value;
}

struct mem {
	reg base;
	imm offset;
}

enum mnemonic : ubyte {
	add,
	bx,
	cmp,			
	ldr_w,
	wfe,			// wait for event
	invalid
}

// ============
//  Parse Enum
// ============

private T parse_enum(T, string file = __FILE__, size_t line = __LINE__)(string s)
    if (is(T == enum))
{
    static const string[] validNames = [ __traits(allMembers, T) ];

    string norm = s.replace('.', '_');
    
    try return norm.to!T;
    catch (ConvException e)
        throw new ConvException(format!"Invalid %s '%s' (valid: %(%s, %))"(
            T.stringof, s, validNames), file, line);
}

// ================
//  Parse Mnemonic
// ================

alias parse_mnemonic = parse_enum!mnemonic;

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "ldr.w";
    auto result = parse_mnemonic(s);
    assert(result == mnemonic.ldr_w);
}

alias operand = Algebraic!(reg, imm, mem);

struct instr {
	uint addr;
	mnemonic opcode;
	operand[] operands;
}

struct stm32f4_rcc {
	enum cr         = 0x40023800;	// clock control
	enum pll_cfgr   = 0x40023804;	// pll config
	enum cfgr       = 0x40023808;	// clock config
	enum cir		= 0x4002380c;	// clock interrupt
	enum ahb1_enr	= 0x40023830;	// advanced high performance bus
}

struct stm32f4_rcc_cr {
	enum hsion		= 0;
	enum hsirdy		= 1;
	enum hsitrim	= 2;
	enum hseon		= 8;
	enum hserdy		= 9;
	enum hsebyp		= 16;
	enum csson		= 18;	// clock security system enable
	enum pllon		= 19;
	enum pllrdy		= 20;
	enum plli2son	= 24;
	enum plli2srdy  = 25;
}

struct stm32f4_rcc_pllcfgr {
	enum pllm 		= 0;	// division factor
	enum plln       = 6;	// multiplication factor
	enum pllp		= 16;	// pll output division
	enum pplsrc		= 19;
	enum pplq		= 24;
}

struct stm32f4_rcc_apb1enr {
	enum tim2 		= 0;
	enum tim3 		= 1;
	enum tim5		= 4;
	enum spi2		= 17;
	enum i2c1		= 21;
	enum i2c2		= 22;
	enum i2c3		= 23;
	enum uart4		= 28;
	enum uart5		= 29;
	enum usart2		= 31;
}

struct stm32f4_dac_cr {
	enum em1		= 0;	// enable DAC channel 1
	enum boff1		= 1;	// output buffer disable
	enum ten1		= 2;	// trigger enable
	enum tsel1		= 3;	// trigger source select
	enum wave1		= 6;	// noise/triangle enable
	enum mamp1		= 8;	// wave amplitude
	enum dmaen1		= 12;	// DMA enable
}

struct stm32f4_swtrigr {
	enum swtrig1 	= 0;
	enum swtrig2	= 1;
}

enum instr_grp : ubyte {
	alu_imm			= 0b00,
	data_proc		= 0b010000,
	single_str_1    = 0b0101,
	single_str_2	= 0b011,
	single_str_3    = 0b100
}

enum alu_imm : ubyte {
	add_8           = 0b110,
	add_3 			= 0b01110,
	asr             = 0b010,
	cmp				= 0b101,
	lsl             = 0b000,
	lsr 			= 0b001,
	movs            = 0b100,
	subs_8			= 0b111
}

enum data_proc : ubyte {
	and 			= 0b0000,
	lor 			= 0b1100,
	mvn             = 0b1111
}

enum single_str : ubyte {
	str 			= 0b000,
	strh  			= 0b001
}

enum opcode : ubyte {
	add_imm_3,
	add_imm_8,
	and_reg,
	lor_reg,
	mvn_reg,
	asr_imm,
	cmp_imm,
	ldrb_imm,
	ldr_imm,
	lsl_imm,
	lsr_imm,
	ldrh_imm,
	mov_imm,
	str_reg,
	str_imm,
	strh_reg,
	strb_imm,
	strh_imm,
	sub_imm_8,
	invalid
}

// =================
//  Decode Mnemonic
// =================

opcode decode_mnemonic(ushort instr) { 
    if (cast(ubyte)((instr >> 14) & 0b11) == instr_grp.alu_imm) {
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.cmp) {
    		return opcode.cmp_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.movs) {
    		return opcode.mov_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.subs_8) {
    		return opcode.sub_imm_8;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b11111) == alu_imm.add_3) {
    		return opcode.add_imm_3;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.add_8) {
    		return opcode.add_imm_8;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.asr) {
    		return opcode.asr_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.lsl) {
    		return opcode.lsl_imm;
    	}
    	if (cast(ubyte)((instr >> 11) & 0b111) == alu_imm.lsr) {
    		return opcode.lsr_imm;
    	}
    }
    if (cast(ubyte)((instr >> 10) & 0b111111) == instr_grp.data_proc) {
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.and) {
    		return opcode.and_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.lor) {
    		return opcode.lor_reg;
    	}
    	if (cast(ubyte)((instr >> 6) & 0b1111) == data_proc.mvn) {
    		return opcode.mvn_reg;
    	}
    }
    if (cast(ubyte)((instr >> 12) & 0b1111) == instr_grp.single_str_1) {
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.str) {
    		return opcode.str_reg;
    	}
    	if (cast(ubyte)((instr >> 9) & 0b111) == single_str.strh) {
    		return opcode.strh_reg;
    	}
    }
    if (cast(ubyte)((instr >> 13) & 0b111)  == instr_grp.single_str_2) {
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.str_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldr_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.strb_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 1) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldrb_imm;
    		}
    	}
    }
    if (cast(ubyte)((instr >> 13) & 0b111)  == instr_grp.single_str_3) {
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 0) {
    			return opcode.strh_imm;
    		}
    	}
    	if (cast(ubyte)((instr >> 12) & 0b1) == 0) {
    		if (cast(ubyte)((instr >> 11) & 0b1) == 1) {
    			return opcode.ldrh_imm;
    		}
    	}
    }
    return opcode.invalid;
}

struct instr_16 {
	opcode op;
	reg rd;
	reg rm;
	reg rn;
	ubyte imm;
}

instr_16 parse_cmp_imm(short instr) {
	instr_16 res;
	res.op = opcode.cmp_imm;
	ubyte rn = cast(ubyte)((instr >> 8) & 0b111);
	ubyte imm = cast(ubyte)(instr & 0xff);
	res.imm = imm;
	res.rn = cast(reg)(rn);
	return res;
}

instr_16 decode_instr(ushort instr) {
	instr_16 res;
	auto op = decode_mnemonic(instr);
	if (op == opcode.cmp_imm) {
		return parse_cmp_imm(instr);
	}
	return res;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		instr_16 expected;
	}

	test_case[] tests = [
		test_case(0x2b00, instr_16( op: opcode.cmp_imm, rn: reg.r3, imm: 0 ))
	];

	foreach (t; tests) {
		assert(
		    decode_instr(t.instr) == t.expected,
		    format("Failed for instruction 0x%04X", t.instr)
		);
    }
} 

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		opcode expected;
	}

	test_case[] tests = [
		test_case(0x10b6, opcode.asr_imm),
		test_case(0x3730, opcode.add_imm_8),
		test_case(0x4013, opcode.and_reg),
		test_case(0x2b00, opcode.cmp_imm),
		test_case(0x2300, opcode.mov_imm),
		test_case(0x3902, opcode.sub_imm_8),
		test_case(0x00d9, opcode.lsl_imm),
		test_case(0x099b, opcode.lsr_imm),
		test_case(0x4313, opcode.lor_reg),
		test_case(0x43db, opcode.mvn_reg),
		test_case(0x608b, opcode.str_imm),
		test_case(0x80fb, opcode.strh_imm),
		test_case(0x88fb, opcode.ldrh_imm),
		test_case(0x781a, opcode.ldrb_imm),
		test_case(0x701a, opcode.strb_imm),
		test_case(0x68fb, opcode.ldr_imm)
	];

	foreach (t; tests) {
		assert(
		    decode_mnemonic(t.instr) == t.expected,
		    format("Failed for instruction 0x%04X", t.instr)
		);
    }
}

// ================
//  Remove Comment
// ================

string remove_comment(string line) {
	size_t at_pos = line.indexOf('@');
	if (at_pos != -1) {
		line = line[0 .. at_pos];
	}
	return strip(line, " \t");
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "800a18c: f8df d034  ldr.w sp, [pc, #52]  @ 800a1c4 <LoopFillZerobss+0xe>";
    auto result = remove_comment(s);
    assert(result.length == 39, "remove_comment return value not the correct length");
    assert(result == "800a18c: f8df d034  ldr.w sp, [pc, #52]",
    	   "remove_comment did not trim correctly");
}

// ========
//  Is Hex
// ========

bool is_hex(dchar c) {
    return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}

// ==========
//  Get Addr
// ==========

string get_addr(string instr_str)
in {
    assert(instr_str.length >= 8, "instr_str too short");
    assert(instr_str[7] == ':', "Expected ':' at 8th position");
} 
body {
	return instr_str[0 .. 7];
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "800a18c: f8df d034  ldr.w sp, [pc, #52]";
    auto result = get_addr(s);
    assert(result == "800a18c");
}

// =============
//  Remove Addr
// =============

string remove_addr(string line) {
	size_t colon_pos = line.indexOf(':');
	if (colon_pos != -1) {
		line = line[(colon_pos + 1) .. $];
	} 
	return stripLeft(line, " \t");
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "800a18c: f8df d034  ldr.w sp, [pc, #52]";
    auto result = remove_addr(s);
    assert(result == "f8df d034  ldr.w sp, [pc, #52]");
}

// ===========
//  Get Bytes
// ===========

string get_bytes(string line)
out(result) {
    assert(result.length == 4 || result.length == 8,
           "Return value must be 4 or 8 characters");
}
body {
	string result;
	while (true) {
		auto bytes = line[0 .. 4];
		if (bytes.all!(c => is_hex(c))) {
			result ~= bytes;
			line = line[5 .. $];
		} else {
			break;
		}
		line = stripLeft(line, " \t");
	}
	return result;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "f8df d034  ldr.w sp, [pc, #52]";
    auto result = get_bytes(s);
    assert(result == "f8dfd034");
}

// ==============
//  Remove Bytes
// ==============

string remove_bytes(string line) {
	while (true) {
		auto bytes = line[0 .. 4];
		if (bytes.all!(c => is_hex(c))) {
			line = line[5 .. $];
		} else {
			break;
		}
		line = stripLeft(line, " \t");
	}
	return line;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "f8df d034  ldr.w sp, [pc, #52]";
    auto result = remove_bytes(s);
    assert(result == "ldr.w sp, [pc, #52]");
}

// ==============
//  Get Mnemonic
// ==============

string get_mnemonic(string line) 
out(result) {
    assert(line.length > 0,
           "Return value must not be empty");
}
body {
	string result = line;
	size_t space_pos = line.indexOf(' ');
	if (space_pos != -1) {
		result = line[0 .. space_pos];
	}
	return result;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "ldr.w sp, [pc, #52]";
    auto result = get_mnemonic(s);
    assert(result == "ldr.w");
}

// =================
//  Remove Mnemonic
// =================

string remove_mnemonic(string line) {
	string result = line;
	size_t space_pos = line.indexOf(' ');
	if (space_pos != -1) {
		result = result[(space_pos + 1) .. $];
	}
	return stripLeft(result, " \t");
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
    string s = "ldr.w sp, [pc, #52]";
    auto result = remove_mnemonic(s);
    assert(result == "sp, [pc, #52]");
}

// ==============
//  Get Operands
// ==============

string get_operands(string line) {
	string result = line;
	return result;
}

struct cortex_m_cpu {
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
	uint sp;
	uint ldr;
	uint pc;

	bool n;
	bool z;
	bool c;
	bool v;
}

