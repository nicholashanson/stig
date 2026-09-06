import std.format;
import std.conv      : to;
import std.typecons  : tuple, Tuple;
import std.array;
import std.traits    : Parameters, ReturnType;
import std.regex;
import std.string    : indexOf;
import std.stdio;

import cortex_m_core;
import memory_sections;
import vm;

import thumb_2_opcodes;
import thumb_2_opcode_defs;
import thumb_2_instrs;
import thumb_2_decode_instr;

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
version (ARMv8_M) {
  import vm8_loop;
  import vm8_M_se;
  import helium;
  import floating_point_and_vector_move_and_coprocessor_register;
}

// =========================
//  Convert Instr to String
// =========================

string convert_instr_to_string(T1,T2)(T1 instr, const condition cond = condition.none)
{
	T2 parsed_instr = decode_instr!(T2,T1)(instr);
	string res;
	opcode op 	    = parsed_instr.op;

    final switch (op)
    {
        static foreach (member; __traits(allMembers, opcode))
        {
            case mixin("opcode." ~ member):
                static if (__traits(compiles, mixin("convert_" ~ member ~ "_to_string(parsed_instr, cond)")))
				{
                    res = mixin("convert_" ~ member ~ "_to_string(parsed_instr, cond)");
                    return res;
                }
                else
                {
                	assert(0, format("Opcode unhandled: %s, %08X", op.to!string, instr));
                }
        }
    }
    assert(0, format("Opcode unhandled: %s", op.to!string));
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		ushort instr;
		string expected;
		condition cond = condition.none;
	}

	test_case[] tests = [
		test_case(0x2b00, 					"cmp r3, #0"),
		test_case(0x10b6, 			   "asrs r6, r6, #2"),
		test_case(0x3730, 				  "adds r7, #48"),
		test_case(0x4013, 				   "ands r3, r2"),
		test_case(0x2300, 				   "movs r3, #0"),		
		test_case(0x3902, 				   "subs r1, #2"),
		test_case(0x00d9, 			   "lsls r1, r3, #3"),
		test_case(0x099b, 			   "lsrs r3, r3, #6"),
		test_case(0x4313, 				   "orrs r3, r2"),
		test_case(0x43db, 				   "mvns r3, r3"),
		test_case(0x4283, 					"cmp r3, r0"),
		test_case(0x1a1b, 			   "subs r3, r3, r0"),
		test_case(0x469d, 					"mov sp, r3"),		
		test_case(0x460f, 					"mov r7, r1"),
		test_case(0xaf00, 			    "add r7, sp, #0"),
		test_case(0xb092, 				   "sub sp, #72"),
		test_case(0x1d3b, 			   "adds r3, r7, #4"),
		test_case(0x4413, 					"add r3, r2"),
		test_case(0x409a, 				   "lsls r2, r3"),
		test_case(0x40da, 				   "lsrs r2, r3"),	
		test_case(0xa201, 				"add r2, pc, #4"),
		test_case(0x4652, 				    "mov r2, sl"),
		test_case(0x9300, 			  "str r3, [sp, #0]"),
		test_case(0x1891, 			   "adds r1, r2, r2"),
		test_case(0x458c, 					"cmp ip, r1"),
		test_case(0x4463, 					"add r3, ip"),		
		test_case(0x1e54, 			   "subs r4, r2, #1"),
		test_case(0x44e6, 				    "add lr, ip"),
		test_case(0x4572, 					"cmp r2, lr"),
		test_case(0x4241,  				   "negs r1, r0"),
		test_case(0x608b, 			  "str r3, [r1, #8]"),
		test_case(0x80fb, 			 "strh r3, [r7, #6]"),
		test_case(0x88fb, 			 "ldrh r3, [r7, #6]"),
		test_case(0x781a, 			 "ldrb r2, [r3, #0]"),
		test_case(0x701a, 			 "strb r2, [r3, #0]"),
		test_case(0x68fb, 			 "ldr r3, [r7, #12]"),
		test_case(0x4803, 			 "ldr r0, [pc, #12]"),
		test_case(0xb510, 				 "push {r4, lr}"),
		test_case(0xbd10, 			 	  "pop {r4, pc}"),
		test_case(0x5cd3, 			 "ldrb r3, [r2, r3]"),
		test_case(0x58fb, 			  "ldr r3, [r7, r3]"),
		test_case(0x50c4, 			  "str r4, [r0, r3]"),
		test_case(0xb2db, 				   "uxtb r3, r3"),
		test_case(0x415b, 				   "adcs r3, r3"),
		test_case(0xbf08, 						 "it eq"),
		test_case(0xbf1c, 						"itt ne"),
		test_case(0x9d08, 			 "ldr r5, [sp, #32]"),
		test_case(0xb083, 				   "sub sp, #12"),
		test_case(0xb0c0, 			      "sub sp, #256"),
		test_case(0xb580, 				 "push {r7, lr}"),
		test_case(0xb082, 					"sub sp, #8"),
		test_case(0xaf00, 				"add r7, sp, #0"),
		test_case(0x6078, 			  "str r0, [r7, #4]"),
		test_case(0x687b, 			  "ldr r3, [r7, #4]"),
		test_case(0x2b00, 				    "cmp r3, #0"),
		test_case(0x2301, 				   "movs r3, #1"),
		test_case(0x687b, 			  "ldr r3, [r7, #4]"),
		test_case(0x9301, 			  "str r3, [sp, #4]"),
        test_case(0xb480, 					 "push {r7}"),
        test_case(0xb083, 				   "sub sp, #12"),
        test_case(0xaf00, 				"add r7, sp, #0"),
        test_case(0x2300, 		     	   "movs r3, #0"),
        test_case(0x607b,             "str r3, [r7, #4]"),
        test_case(0x4b0f,            "ldr r3, [pc, #60]"),
        test_case(0x6c5b,            "ldr r3, [r3, #68]"),
        test_case(0x4a0e,            "ldr r2, [pc, #56]"),
        test_case(0x6453,            "str r3, [r2, #68]"),
        test_case(0x4b0c,            "ldr r3, [pc, #48]"),
        test_case(0x6c5b,            "ldr r3, [r3, #68]"),
        test_case(0x607b,             "str r3, [r7, #4]"),
        test_case(0x687b,             "ldr r3, [r7, #4]"),
        test_case(0x2300,                  "movs r3, #0"),
        test_case(0x603b,             "str r3, [r7, #0]"),
        test_case(0x4b08,            "ldr r3, [pc, #32]"),
        test_case(0x6c1b,            "ldr r3, [r3, #64]"),
        test_case(0x4a07,            "ldr r2, [pc, #28]"),
        test_case(0x6413,            "str r3, [r2, #64]"),
        test_case(0x4b05,            "ldr r3, [pc, #20]"),
        test_case(0x6c1b,            "ldr r3, [r3, #64]"),
        test_case(0x603b,             "str r3, [r7, #0]"),
        test_case(0x683b,             "ldr r3, [r7, #0]"),
        test_case(0x370c,           	  "adds r7, #12"),
        test_case(0x46bd,                   "mov sp, r7"),
        test_case(0xbc80, 					  "pop {r7}"), 
        test_case(0xbdf8, "pop {r3, r4, r5, r6, r7, pc}"),
 		test_case(0xdf02, 						 "svc 2"),
        test_case(0xb2a4, 				   "uxth r4, r4"),
        test_case(0x4208,      			    "tst r0, r1"),
        test_case(0x4042,      			   "eors r2, r0"),
        test_case(0xb208,      			   "sxth r0, r1"),
        test_case(0xc303,      	   "stmia r3!, {r0, r1}"),
        test_case(0xcc03,      	   "ldmia r4!, {r0, r1}"),
        test_case(0x41b9,      			   "sbcs r1, r7"),
        test_case(0x5b1b,   		 "ldrh r3, [r3, r4]"),
        test_case(0x549d,      		 "strb r5, [r3, r2]"),
        test_case(0x4108,      			   "asrs r0, r1"),
        test_case(0xba2e,      				"rev r6, r5"),
        test_case(0x53dd,     		 "strh r5, [r3, r7]"),
        test_case(0xb661,      				   "cpsie f"),
        test_case(0xb248,    			   "sxtb r0, r1"),
        test_case(0x438a,      			   "bics r2, r1"),
        test_case(0x5688,      		"ldrsb r0, [r1, r2]"),
        test_case(0xba52,      			  "rev16 r2, r2"),
        test_case(0x42da,      				"cmn r2, r3")
	]; 

	foreach (t; tests) {
		string actual = convert_instr_to_string!(ushort,instr_16)(t.instr, t.cond);
		assert(
		    actual == t.expected,
		    format("Failed for instruction [0x%04X], got '%s'", t.instr, actual)
		);
    }
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unittest {
	struct test_case {
		uint instr;
		string expected;
		condition cond = condition.none;
	}

	test_case[] tests = [
		test_case(0xeb43050c, 							      "adc.w r5, r3, ip"),
		test_case(0xfa47f505, 							      "asr.w r5, r7, r5"),
		test_case(0xf0030310, 							     "and.w r3, r3, #16"),
		test_case(0xf0030301, 							      "and.w r3, r3, #1"),
		test_case(0xf0030307, 							      "and.w r3, r3, #7"),
		test_case(0xf003021f, 							     "and.w r2, r3, #31"),
		test_case(0xf36f0208, 							   	    "bfc r2, #0, #9"),
		test_case(0xf0230301, 							      "bic.w r3, r3, #1"),
		test_case(0xf4225200, 						       "bic.w r2, r2, #8192"),
		test_case(0xea230302, 	   						      "bic.w r3, r3, r2"),
		test_case(0xe8bd83f8,    "ldmia.w sp!, {r3, r4, r5, r6, r7, r8, r9, pc}"),
		test_case(0xf8dfd034, 							   "ldr.w sp, [pc, #52]"), 
		test_case(0xf893303d, 						      "ldrb.w r3, [r3, #61]"),
		test_case(0xf9973007, 						      "ldrsb.w r3, [r7, #7]"),
		test_case(0xfa02f303, 								  "lsl.w r3, r2, r3"),
		test_case(0xfa22f303, 								  "lsr.w r3, r2, r3"),
		test_case(0xfa22f303, 								  "lsr.w r3, r2, r3"),
		test_case(0xfb061100, 							    "mla r1, r6, r0, r1"),
		test_case(0xfb00331e, 							    "mls r3, r0, lr, r3"),
		test_case(0xf04f31ff, 						     "mov.w r1, #4294967295"),
		//test_case(0xf64f03ff, 								"movw r3, #63743"),
		test_case(0xf3ef8305, 								      "mrs r3, IPSR"),
		test_case(0xf3838812, 							   "msr BASEPRI_MAX, r3"),
		test_case(0xfb02f303, 							      "mul.w r3, r2, r3"),
		test_case(0xf06f0015, 							     	 "mvn.w r0, #21"),
		test_case(0xea620205, 								    "orn r2, r2, r5"),
		test_case(0xf4437300, 							    "orr.w r3, r3, #512"),
		test_case(0xf4436380, 						       "orr.w r3, r3, #1024"),
		test_case(0xf4437380, 							    "orr.w r3, r3, #256"),
		test_case(0xf1c10720, 						    	   "rsb r7, r1, #32"),
		test_case(0xeb66060c, 								  "sbc.w r6, r6, ip"),
		test_case(0xeb660203, 								  "sbc.w r2, r6, r3"),
		test_case(0xe8801ff0, "stmia.w r0, {r4, r5, r6, r7, r8, r9, sl, fp, ip}"),
		test_case(0xf8c46188, 						   	  "str.w r6, [r4, #392]"),
		test_case(0xf8c73098, 						   	  "str.w r3, [r7, #152]"),
		test_case(0xf8832300, 						     "strb.w r2, [r3, #768]"),
		test_case(0xf883203c, 						   	  "strb.w r2, [r3, #60]"),
		test_case(0xf8832034, 						   	  "strb.w r2, [r3, #52]"),
		test_case(0xe9c54700, 						   	     "strd r4, r7, [r5]"),
		test_case(0xe96dce04, 						  "strd ip, lr, [sp, #-16]!"),
		test_case(0xf1ad0c08, 						    	  "sub.w ip, sp, #8"),
		test_case(0xeba30605, 						   		  "sub.w r6, r3, r5"),
		test_case(0xfa82f24c, 						   		  "uadd8 r2, r2, ip"),
		test_case(0xf3c202c0, 						   	   "ubfx r2, r2, #3, #1"),
		test_case(0xf3c13113, 						     "ubfx r1, r1, #12, #20"),
		test_case(0xfbb3f3f1, 						   	       "udiv r3, r3, r1"),
		test_case(0xfba32302, 						      "umull r2, r3, r3, r2"),
		test_case(0xfa1ff68c, 						        	 "uxth.w r6, ip"),
		test_case(0xea6f4303,    						 "mvn.w r3, r3, lsl #16"),
		test_case(0xe8830003, 							  "stmia.w r3, {r0, r1}"),
		test_case(0xf3420200, 							   "sbfx r2, r2, #0, #1"),
		test_case(0xf837c012, 				       "ldrh.w ip, [r7, r2, lsl #1]"),
		test_case(0xf8180006, 							   "ldrb.w r0, [r8, r6]"),
		test_case(0xf8059000, 							   "strb.w r9, [r5, r0]"),
		test_case(0xf8180006, 							   "ldrb.w r0, [r8, r6]"),
		test_case(0xf8237b02, 							   "strh.w r7, [r3], #2"),
		test_case(0xfa5ff788, 									 "uxtb.w r7, r8"),
		test_case(0xebb31fd2, 	                          "cmp.w r3, r2, lsr #7"),
		test_case(0xebc404c4, 							"rsb r4, r4, r4, lsl #3"),
		test_case(0xe9030007, 							"stmdb r3, {r0, r1, r2}"),
		test_case(0xe9120007, 							"ldmdb r2, {r0, r1, r2}"),
		test_case(0xfa13f389, 								  "uxtah r3, r3, r9"),
		test_case(0xfa0ffe8e, 									 "sxth.w lr, lr"),
		test_case(0xfb13f302, 								 "smulbb r3, r3, r2"),
		test_case(0xfbe20103, 							  "umlal r0, r1, r2, r3"),
		test_case(0xfaa4f28c, 									"sel r2, r4, ip"),
		test_case(0xf9330010, 					  "ldrsh.w r0, [r3, r0, lsl #1]"),
		test_case(0xfbe15366, 							  "umaal r5, r3, r1, r6"),
		test_case(0xf0900f00, 	  								    "teq r0, #0"),
		test_case(0xea5f0030, 								"movs.w r0, r0, rrx"),
		test_case(0xfbc50106, 	  						  "smlal r0, r1, r5, r6"),
		test_case(0xfb14340a, 							 "smlabb r4, r4, sl, r3"),
		test_case(0xfa09f686, 								  "sxtah r6, r9, r6"),
		test_case(0xfa52f080, 								  "uxtab r0, r2, r0"),
		test_case(0xf8a42090, 							 "strh.w r2, [r4, #144]"),
		test_case(0xf5b37ffa, 									"cmp.w r3, #500"),
		test_case(0xf8423f10, 						      "str.w r3, [r2, #16]!"),
		test_case(0xe92d4ff0,  "stmdb sp!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}"),
		test_case(0xeb030384, 						  "add.w r3, r3, r4, lsl #2"),
		test_case(0xf10009bc, 								"add.w r9, r0, #188"),
		test_case(0xf8115b08, 							   "ldrb.w r5, [r1], #8"),
		test_case(0xf3bf8f6f, 											"isb sy"),
		test_case(0xe9d20300, 								 "ldrd r0, r3, [r2]"),
		test_case(0xf0110f40, 									 "tst.w r1, #64"),
		test_case(0xf8521023, 					    "ldr.w r1, [r2, r3, lsl #2]"),
		test_case(0xf85deb04, 							    "ldr.w lr, [sp], #4"),
		test_case(0xf36c0000, 								"bfi r0, ip, #0, #1"),
		test_case(0xf8248032, 	 				   "strh.w r8, [r4, r2, lsl #3]"),
		test_case(0xfab0f080, 										"clz r0, r0"),
		test_case(0xf1720200, 								 "sbcs.w r2, r2, #0"),
		test_case(0xf8021b02, 							   "strb.w r1, [r2], #2"),
		test_case(0xe894000f, 					  "ldmia.w r4, {r0, r1, r2, r3}"),
		test_case(0xf1100f78, 									"cmn.w r0, #120"),
		test_case(0xe8dff003, 									  "tbb [pc, r3]"),
		test_case(0xfa94f5a4, 									   "rbit r5, r4"),
		test_case(0xea07070a, 								  "and.w r7, r7, sl"),
		test_case(0xea4f0887,							  "mov.w r8, r7, lsl #2"),
		test_case(0xf8482003, 								"str.w r2, [r8, r3]"),
		test_case(0xf4843380, 							  "eor.w r3, r4, #65536"),
		test_case(0xf1440400, 								  "adc.w r4, r4, #0"),
		test_case(0xea8212d3, 					      "eor.w r2, r2, r3, lsr #7"),
		test_case(0xea4f0555, 							  "mov.w r5, r5, lsr #1"),
		test_case(0xf063037f, 								  "orn r3, r3, #127"),
		test_case(0xea4f0e62, 							  "mov.w lr, r2, asr #1"),
		test_case(0xea940f05,  										"teq r4, r5"),
		test_case(0xf20733e7, 								 "addw r3, r7, #999"),
		test_case(0xea190f03, 									  "tst.w r9, r3"),
		test_case(0xfb8b0100, 							  "smull r0, r1, fp, r0"),
		test_case(0xf04f5380, 						      "mov.w r3, #268435456"),
		test_case(0xf2a54535,        						"subw r5, r5, #1077"),
		test_case(0xfa4ff38a,									 "sxtb.w r3, sl"),
		test_case(0xf9156c62, 							"ldrsb.w r6, [r5, #-98]"),
		test_case(0xf890f000, 										  "pld [r0]"),
		test_case(0xf9b1100e, 							 "ldrsh.w r1, [r1, #14]"),
		test_case(0xe8533f00, 									"ldrex r3, [r3]"),
		test_case(0xe8b04ff0,"ldmia.w r0!, {r4, r5, r6, r7, r8, r9, sl, fp, lr}")
	];

	foreach (t; tests) {
		string actual = convert_instr_to_string!(uint,instr_32)(t.instr, t.cond);
		assert(
		    actual == t.expected,
		    format("Failed for instruction [0x%04X], got '%s'", t.instr, actual)
		);
    }
}
// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// ================
//  REG CACHE ITEM
// ================

struct reg_cache_item {
    uint    val;
    string    s;
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
reg_cache_item[16] reg_cache;
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// ==========
//  ROW VIEW
// ==========

struct row_view {
    enum kind { func_name, blank_line, instr };
    kind    type;
    string     s;
    uint    addr;
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// ========================
//  GENERATE FUNCTION ROWS
// ========================

row_view[] get_function_rows(func f) {
	row_view[] res;
	res ~= row_view(type: row_view.kind.func_name, s: f.name);
	foreach (ins; f.instrs) {
        string s;
        try {
            auto i16 = ins.i.get!instr_16;
            s = convert_instr_to_string!(ushort,instr_16)(ins._in_16);
            s = s.replace("<label>", format("%x", ins._addr + i16.offset + 4));
            if (i16.op == opcode.ldr_lit_t1) {
                int base = ins._addr + 4;
                base &= ~0x3;
                s ~= format(" @ (%X)", base + i16.imm);
            }
        }
        catch (Exception e) {
            try {
                auto i32 = ins.i.get!instr_32;
            	s = convert_instr_to_string!(uint,instr_32)(ins._in_32);
                s = s.replace("label", format("%x", ins._addr + i32.offset + 4));
            }
            catch (Exception) {
                s = "Unknown instruction type";
            }
        }

        assert(s.length != 0, "instruction string is empty");
        if (ins._instr_bytes.length == 8) {
            res ~= row_view(type: row_view.kind.instr,
                            addr: ins._addr, 
                            s: format("%x: %s     %s",     ins._addr, ins._instr_bytes, s));
        } else {
            res ~= row_view(type: row_view.kind.instr,
                            addr: ins._addr, 
                            s: format("%x: %s         %s", ins._addr, ins._instr_bytes, s));
        }
    }
    return res;
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// =====================
//  GENERATE INSTR ROWS
// =====================

row_view[] generate_instr_rows(func[] funcs) {
    row_view[] res;
    foreach (f; funcs) {
        res ~= get_function_rows(f);
        res ~= row_view(type: row_view.kind.blank_line);
    }
    return res;
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
immutable string[] regs = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9",
                           "sl","fp","ip","sp","lr","pc"];
// ---------------------------------------------------------------------------------------                       

// ---------------------------------------------------------------------------------------
// =======================
//  SPLIT LOAD STORE LINE
// =======================

string[] split_load_store_line(string s) {
	enum parenth_pattern = `\[[^\]]*\]|\([^\)]*\)`;
	auto re = regex(parenth_pattern);

	string[] tokens;
	size_t last_end = 0;

	foreach (m; matchAll(s, re)) 
        tokens ~= m.hit;

    assert(tokens.length == 4, format("Number of tokens is %d", tokens.length));
    auto split_note = split_load_store_note(tokens[3][1 .. $ - 1]);
    tokens = tokens[0 .. $ - 1];
    assert(split_note.length >= 4);
    tokens ~=  split_note[0];
    tokens ~= (split_note[1] ~ " " ~ split_note[2]);
    tokens ~=  split_note[3];
    tokens ~=  split_note[4];
    return tokens;
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// =======================
//  SPLIT LOAD STORE NOTE
// =======================

string[] split_load_store_note(string s) {
    auto res = s.split(" ");
    assert(res.length == 4);

    string last = res[3];
    string base;
    string tag;

    auto lb = last.indexOf('[');
    if (lb == -1) {
        base = last;
        tag = "";
    } else {
        base = last[0 .. lb];
        tag = last[lb .. $]; 
    }
    return [res[0], res[1], res[2], base, tag];
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
unittest {
	string   test_str  = "[20][8000C08][relocate_vector_table](0x08000000 stored into 0xE000ED08[VTOR])";
	string   test_str2 = "[1][8001A20][z_arm_reset](0x20001C80 loaded from 0x08001A4C)";
	string 	 test_str3 = "[7865][8002518][config_enable_default_clocks](0x00000000 loaded from 0x40023840[RCC_APB1ENR])";
	string[] expected = [
		"[20]",
		"[8000C08]",
		"[relocate_vector_table]",
		"0x08000000",
		"stored into",
		"0xE000ED08",
		"[VTOR]"
	];
	auto res  = split_load_store_line(test_str);
	auto res2 = split_load_store_line(test_str2);
	auto res3 = split_load_store_line(test_str3);
	writeln(res);
	assert(res == expected);
}
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// ==================
//  SPLIT INSTR LINE
// ==================

string[] split_instr_line(string s) {
    enum reg_pattern = `\b(r[0-9]|sl|fp|ip|sp|lr|pc)\b`;
    auto re = regex(reg_pattern);

    string[] tokens;
    size_t last_end = 0;

    foreach (m; matchAll(s, re)) {
        size_t start = cast(size_t)(m.hit.ptr - s.ptr);
        size_t end   = start + m.hit.length;
        if (start > last_end)
            tokens ~= s[last_end .. start];
        tokens ~= m.hit;
        last_end = end;
    }
    if (last_end < s.length)
        tokens ~= s[last_end .. $];
    return tokens;
}
// ---------------------------------------------------------------------------------------

