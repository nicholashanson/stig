import std.variant : Algebraic;
import std.conv    : to, ConvException, parse;
import std.format;
import std.stdio;
import std.array;

import cortex_m_core;
import thumb_2_instrs;
import thumb_2_opcodes;
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
import thumb_2_floating_point_ext_32;
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
import thumb_2_mult_mult_acc_32;
import thumb_2_store_single_data_item_32;
import thumb_2_misc_ops_32;
import vm8_M_se;

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

alias instruction = Algebraic!(instr_16, instr_32);

// ============
//  Addr Instr
// ============

struct addr_instr {
    instruction 	  i;
    uint 		 _in_32;
    ushort 		 _in_16;
    uint          _addr;
    string _instr_bytes;

    this(uint addr, string bytes_string) {
        _instr_bytes = bytes_string;
        _addr = addr;
        if (bytes_string.length == 8) {
            _in_32 = parse!uint(bytes_string, 16);
            i = decode_instr!(instr_32,uint)(_in_32);
        }
        if (bytes_string.length == 4) {
            _in_16 = cast(ushort) parse!uint(bytes_string, 16);
            i = decode_instr!(instr_16,ushort)(_in_16);
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// ======
//  Func
// ======

struct func {
    string 				name;
    addr_instr[]  	  instrs;
    uint[uint]  literal_pool;
    byte_table[] byte_tables;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// ==============
//  Decode Instr
// ==============

R decode_instr(R,T)(T instr)
{
    immutable op = decode_mnemonic(instr);
    R res;

    final switch (op)
    {
        static foreach (member; __traits(allMembers, opcode))
        {
            case mixin("opcode." ~ member):
                static if (__traits(compiles, mixin("parse_" ~ member ~ "(instr)")) &&
           					 is(typeof(mixin("parse_" ~ member ~ "(instr)")) == R))
				{
                    res = mixin("parse_" ~ member ~ "(instr)");
                    res.op = op;
                    return res;
                }
                else
                {
                	assert(0, format("Opcode unhandled: %s, instr: 0x%08X", op.to!string, instr));
                }
        }
    }
    assert(0, format("Opcode unhandled: %s", op.to!string));
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		instr_16 expected;
	}

	test_case[] tests = [
		test_case(0x1d3b, instr_16(op: opcode.add_imm_t1, rd: reg.r3,  rn: reg.r7,                           imm: 	  4)),	// adds	r3, r7, #4
		test_case(0x3730, instr_16(op: opcode.add_imm_t2, rd: reg.r7,  rn: reg.r7,                           imm:    48)),	// adds	r1, r2, r2
		test_case(0xaf00, instr_16(op: opcode.add_sp_t1,  rd: reg.r7, 			                             imm: 	  0)),	// add	r7, sp, #0
		test_case(0x1891, instr_16(op: opcode.add_reg_t1, rd: reg.r1,  rn: reg.r2,                           rm: reg.r2)),	// adds	r1, r2, r2
		test_case(0x44e6, instr_16(op: opcode.add_reg_t2, rd: reg.lr,  rn: reg.lr,                           rm:reg.r12)),	// add	lr, ip
		test_case(0xa201, instr_16(op: opcode.adr_t1,     rd: reg.r2,  			                             imm: 	  4)),	// add	r2, pc, #4
		test_case(0x4013, instr_16(op: opcode.and_reg_t1, rd: reg.r3,  rn: reg.r3,                           rm: reg.r2)),	// ands	r3, r2
		test_case(0x10b6, instr_16(op: opcode.asr_imm_t1, rd: reg.r6,  rm: reg.r6,  shift_t: shift_type.asr, imm:     2)),	// asrs	r6, r6, #2
		test_case(0xd002, instr_16(op: opcode.b_t1,       cond: condition.eq,                                offset:  4)),	// beq.n
		test_case(0xd3f9, instr_16(op: opcode.b_t1,		  cond: condition.cc,	                             offset:-14)),
		test_case(0xe7cf, instr_16(op: opcode.b_t2,					 		                                 offset:-98)),
		test_case(0x4798, instr_16(op: opcode.blx_t1,     rm: reg.r3                                                   )),
		test_case(0x4718, instr_16(op: opcode.bx_t1,      rm: reg.r3                                                   )),
		test_case(0xb943, instr_16(op: opcode.cbnz_t1,    rn: reg.r3,			                             offset: 16)),
		test_case(0xb103, instr_16(op: opcode.cbz_t1,     rn: reg.r3,                                        offset:  0)),
		test_case(0x2b00, instr_16(op: opcode.cmp_imm_t1, rn: reg.r3,                                        imm:     0)),
		test_case(0x4283, instr_16(op: opcode.cmp_reg_t1, rn: reg.r3,  rm: reg.r0 			                           )),
		test_case(0x458c, instr_16(op: opcode.cmp_reg_t2, rn: reg.r12, rm: reg.r1                                      )),
		test_case(0x4572, instr_16(op: opcode.cmp_reg_t2, rn: reg.r2,  rm: reg.lr                                      )),
		test_case(0x68fb, instr_16(op: opcode.ldr_imm_t1, rt: reg.r3,  rn: reg.r7,                           imm:    12)), 	// ldr	r3, [r7, #12]
		test_case(0x4803, instr_16(op: opcode.ldr_lit_t1, rt: reg.r0,                                        imm:    12)),
		test_case(0x58fb, instr_16(op: opcode.ldr_reg_t1, rt: reg.r3,  rn: reg.r7,                           rm: reg.r3)),
		test_case(0x781a, instr_16(op: opcode.ldrb_imm_t1,rt: reg.r2,  rn: reg.r3,                           imm: 	  0)), 	// ldrb	r2, [r3, #0]
		test_case(0x5cd3, instr_16(op: opcode.ldrb_reg_t1,rt: reg.r3,  rn: reg.r2,                           rm: reg.r3)),
		test_case(0x88fb, instr_16(op: opcode.ldrh_imm_t1,rt: reg.r3,  rn: reg.r7,                           imm: 	  6)),
		test_case(0x00d9, instr_16(op: opcode.lsl_imm_t1, rd : reg.r1, rm: reg.r3,  shift_t: shift_type.lsl, imm: 	  3)),
		test_case(0x409a, instr_16(op: opcode.lsl_reg_t1, rd: reg.r2,  rn: reg.r2,  						 rm: reg.r3)),
		test_case(0x099b, instr_16(op: opcode.lsr_imm_t1, rd: reg.r3,  rm: reg.r3,  shift_t: shift_type.lsr, imm: 	  6)),
		test_case(0x40da, instr_16(op: opcode.lsr_reg_t1, rd: reg.r2,  rn: reg.r2,                           rm: reg.r3)),
		test_case(0x2300, instr_16(op: opcode.mov_imm_t1, rd: reg.r3,                                        imm: 	  0)), 	// movs	r3, #0
		test_case(0x43db, instr_16(op: opcode.mvn_reg_t1, rd: reg.r3,  rm: reg.r3 			                  		   )),
		test_case(0x4241, instr_16(op: opcode.rsb_imm_t1, rd: reg.r1,  rn: reg.r0                            		   )), 	// negs	r1, r0
		test_case(0xbd10, instr_16(op: opcode.pop_t1,     reg_list: [reg.r4, reg.pc]                         		   )),
		test_case(0xb510, instr_16(op: opcode.push_t1,    reg_list: [reg.r4, reg.lr]                         		   )),
		test_case(0x608b, instr_16(op: opcode.str_imm_t1, rt: reg.r3,  rn: reg.r1,                           imm: 	  8)),
		test_case(0x50c4, instr_16(op: opcode.str_reg_t1, rt: reg.r4,  rn: reg.r0,                           rm: reg.r3)),
		test_case(0x9300, instr_16(op: opcode.str_imm_t2, rt: reg.r3,			                             imm:     0)),
		test_case(0x701a, instr_16(op: opcode.strb_imm_t1,rt: reg.r2,  rn: reg.r3,                           imm: 	  0)),
		test_case(0x80fb, instr_16(op: opcode.strh_imm_t1,rt: reg.r3,  rn: reg.r7,                           imm: 	  6)),
		test_case(0x1e54, instr_16(op: opcode.sub_imm_t1, rd: reg.r4,  rn: reg.r2,                           imm:     1)),
		test_case(0x3902, instr_16(op: opcode.sub_imm_t2, rd: reg.r1,  rn: reg.r1,                           imm: 	  2)),
		test_case(0x1a1b, instr_16(op: opcode.sub_reg_t1, rd: reg.r3,  rn: reg.r3,                           rm: reg.r0)),
		test_case(0x4313, instr_16(op: opcode.orr_reg_t1, rd: reg.r3,  rn: reg.r3,                           rm: reg.r2)),
		test_case(0x469d, instr_16(op: opcode.mov_reg_t1, rd: reg.sp,  rm: reg.r3                            		   )),
		test_case(0x460f, instr_16(op: opcode.mov_reg_t1, rd: reg.r7,  rm: reg.r1                            		   )),
		test_case(0xb092, instr_16(op: opcode.sub_sp_t1,		    			                             imm:    72)),
		test_case(0x4413, instr_16(op: opcode.add_reg_t2, rd: reg.r3,  rn: reg.r3,                           rm: reg.r2)),
		test_case(0x4652, instr_16(op: opcode.mov_reg_t1, rd: reg.r2,  rm: reg.r10                           		   )), 	// mov	r2, sl
		test_case(0x4463, instr_16(op: opcode.add_reg_t2, rd: reg.r3,  rn: reg.r3,                           rm:reg.r12))	// mov	r3, ip
	];

	string fields(const ref instr_16 a, const ref instr_16 b) {
        string[] lines;
        static foreach (member; __traits(allMembers, instr_16)) {
        	mixin("lines ~= \"" ~ member ~ ": \" ~ a." ~ member ~ ".to!string ~ \" vs \" ~ b." ~ member ~ ".to!string ~ \"\\n\";");
    	}
        return lines.join("\n");
    }

	foreach (t; tests) {
		auto res = decode_instr!(instr_16,ushort)(t.instr);
		assert(
		    res == t.expected,
		    format("Failed for instruction 0x%08X:\n%s", t.instr, fields(res, t.expected))
		);
    }
} 

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		uint instr;
		instr_32 expected;
	}

	test_case[] tests = [
		test_case(0xeb0101a3, instr_32(op: opcode.add_reg_t3,  rd: reg.r1,    rn: reg.r1, 	 rm: reg.r3,   shift_t: shift_type.asr, shift_n:  2)),	// add.w	r1, r1, r3, asr #2
		test_case(0xf7ffffda, instr_32(op: opcode.bl_t1, 											       offset: -76						   )),
		test_case(0xf3af8000, instr_32(op: opcode.nop_t2																			 	       )),
		test_case(0xe8bd4008, instr_32(op: opcode.pop_t2, 												   reg_list: [reg.r3, reg.lr] 		   )),
		test_case(0xf5a33a80, instr_32(op: opcode.sub_imm_t3,  rd: reg.r10,   rn: reg.r3, 									   		imm: 65536 )),	// sub.w	sl, r3, #65536	@ 0x10000
		test_case(0xf008ff15, instr_32(op: opcode.bl_t1, 												   offset: 36394 					   )),
		test_case(0xf009f8a6, instr_32(op: opcode.bl_t1, 												   offset: 37196					   )),
		test_case(0xf003030c, instr_32(op: opcode.and_imm_t1,  rd: reg.r3,    rn: reg.r3, 	 unexpanded_imm: 12,				    imm: 12    )),	// and.w	r3, r3, #12
		test_case(0xfbb2f3f3, instr_32(op: opcode.udiv_t1,     rd: reg.r3,    rn: reg.r2, 	 rm: reg.r3 					   				   )),	// udiv	r3, r2, r3
		test_case(0xf3c20208, instr_32(op: opcode.ubfx_t1, 	   rd: reg.r2,    rn: reg.r2, 				   lsb: 0, 					widthm1: 8 )),	// ubfx	r2, r2, #0, #9
		test_case(0xfb02f303, instr_32(op: opcode.mul_t2, 	   rd: reg.r3,    rn: reg.r2, 	 rm: reg.r3 									   )),	// mul.w	r3, r2, r3
		test_case(0xfa22f303, instr_32(op: opcode.lsr_reg_t2,  rd: reg.r3,    rn: reg.r2, 	 rm: reg.r3,   shift_t: shift_type.lsr,		       )),  // lsr.w	r3, r2, r3
		test_case(0xf4434380, instr_32(op: opcode.orr_imm_t1,  rd: reg.r3,    rn: reg.r3, 	 unexpanded_imm: 3200,			   		imm: 16384 )),	// orr.w	r3, r3, #16384	@ 0x4000
		test_case(0xf1070314, instr_32(op: opcode.add_imm_t3,  rd: reg.r3,    rn: reg.r7, 										    imm: 20    )),	// add.w	r3, r7, #20
		test_case(0xf0230310, instr_32(op: opcode.bic_imm_t1,  rd: reg.r3,    rn: reg.r3, 	 unexpanded_imm: 16,					imm: 16    )),	// bic.w	r3, r3, #16
		test_case(0xf64f03ff, instr_32(op: opcode.mov_imm_t3,  rd: reg.r3, 												   			imm: 63743 )),	// movw	r3, #63743	@ 0xf8ff // movw	r3, #63743	@ 0xf8ff
		test_case(0xf9973007, instr_32(op: opcode.ldrsb_imm_t1,rt: reg.r3,    rn: reg.r7, 	 index: true,  add: true,				imm: 7     )),	// ldrsb.w	r3, [r7, #7]
		test_case(0xf8412023, instr_32(op: opcode.str_reg_t2,  rt: reg.r2,    rn: reg.r1, 	 rm: reg.r3, 							shift_n: 2 )),	// str.w	r2, [r1, r3, lsl #2]
		test_case(0xf3bf8f4f, instr_32(op: opcode.dsb_t1 																			 		   )),
		test_case(0xf1c30307, instr_32(op: opcode.rsb_imm_t2,  rd: reg.r3,    rn: reg.r3, 										    imm: 7     )),  // rsb	r3, r3, #7
		test_case(0xfba22303, instr_32(op: opcode.umull_t1,    rd_lo: reg.r2, rd_hi: reg.r3, rn: reg.r2,   rm: reg.r3 				           )),	// umull	r2, r3, r2, r3
		test_case(0xe9c72300, instr_32(op: opcode.strd_imm_t1, add: true,     rt: reg.r2,    rt_2: reg.r3, rn: reg.r7, index: true, imm: 0     )),	// strd	r2, r3, [r7]
		test_case(0xf67fae90, instr_32(op: opcode.b_t3, 	   cond: condition.ls, 						   offset: -736 					   )),	// bls.w	8004360
		test_case(0xe92d4fb0, instr_32(op: opcode.push_t2,     reg_list:[reg.r4, reg.r5, reg.r7, reg.r8, reg.r9, reg.r10, reg.r11, reg.lr]     )),	// stmdb	sp!, {r4, r5, r7, r8, r9, sl, fp, lr}
		test_case(0xea4161d2, instr_32(op: opcode.orr_reg_t2,  rd: reg.r1,    rn: reg.r1, 	 rm:  reg.r2,  shift_t: shift_type.lsr, shift_n: 27)),	// orr.w	r1, r1, r2, lsr #27
		test_case(0xebb2080a, instr_32(op: opcode.sub_reg_t2,rd: reg.r8,set_flags:true,rn: reg.r2,rm: reg.r10,shift_t: shift_type.lsl,shift_n:0)),	// subs.w	r8, r2, sl
		test_case(0xeb63090b, instr_32(op: opcode.sbc_reg_t2,  rd: reg.r9,    rn: reg.r3, 	 rm: reg.r11,  shift_t: shift_type.lsl, shift_n: 0 )),	// sbc.w	r9, r3, fp
		test_case(0xeb45030b, instr_32(op: opcode.adc_reg_t2,  rd: reg.r3,    rn: reg.r5, 	 rm: reg.r11,  shift_t: shift_type.lsl, shift_n: 0 )),	// adc.w	r3, r5, fp
		test_case(0xf06f0240, instr_32(op: opcode.mvn_imm_t1,  rd: reg.r2, 	  unexpanded_imm: 64,									imm: 64    )),	// mvn.w	r2, #64	@ 0x40 
		test_case(0xe8533f00, instr_32(op: opcode.ldrex_t1,    rt: reg.r3,    rn: reg.r3 												       )),	// ldrex	r3, [r3]
		test_case(0xe8412300, instr_32(op: opcode.strex_t1,    rd: reg.r3,    rt: reg.r2, 	 rn: reg.r1 									   )),	// strex	r3, r2, [r1]
		test_case(0xfb0e7711, instr_32(op: opcode.mls_t1,      rd: reg.r7, 	  rn: reg.lr, 	 rm: reg.r1,   ra: reg.r7						   )),	// mls	r7, lr, r1, r7
		//test_case(0xf9b4500c, instr_32(op: opcode.ldrsh_reg_t1,rt: reg.r5,    rn: reg.r4, 										    imm: 12    )),	// ldrsh.w	r5, [r4, #12]
		test_case(0xea1c0f0e, instr_32(op: opcode.tst_reg_t2,  rn: reg.r12, 			   	 rm: reg.lr,   shift_t: shift_type.lsl             )),	// tst.w	ip, lr
		test_case(0xea010808, instr_32(op: opcode.and_reg_t2,  rd: reg.r8,    rn: reg.r1, 	 rm: reg.r8									 	   )),	// and.w	r8, r1, r8 
		test_case(0xea23030c, instr_32(op: opcode.bic_reg_t2,  rd: reg.r3,    rn: reg.r3, 	 rm: reg.r12 									   )),	// bic.w	r3, r3, ip
		test_case(0xf7ffbfbb, instr_32(op: opcode.b_t4, 												   offset: -138                        )),	// b.w	8009c5c <_fclose_r>
		test_case(0xf8dfd034, instr_32(op: opcode.ldr_lit_t2,  rt: reg.sp, 								   add: true,		   		imm: 52    ))	// ldr.w	sp, [pc, #52]
	];

	string fields(const ref instr_32 a, const ref instr_32 b) {
        string[] lines;
        static foreach (member; __traits(allMembers, instr_32)) {
        	mixin("lines ~= \"" ~ member ~ ": \" ~ a." ~ member ~ ".to!string ~ \" vs \" ~ b." ~ member ~ ".to!string ~ \"\\n\";");
    	}
        return lines.join("\n");
    }

	foreach (t; tests) {
		auto res = decode_instr!(instr_32,uint)(t.instr);
		assert(
		    res == t.expected,
		    format("Failed for instruction 0x%08X:\n%s", t.instr, fields(res, t.expected))
		);
    }
}
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------