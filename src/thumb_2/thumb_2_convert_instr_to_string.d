import std.format;
import std.conv     : to;
import std.typecons : tuple, Tuple;
import std.array    : appender;
import std.traits   : Parameters, ReturnType;

import cortex_m_core;
import memory_sections;
import vm;

import thumb_2_opcodes;
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
import thumb_2_load_store_single_data_item_16;
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
import thumb_2_mult_mult_acc_32;
import thumb_2_store_single_data_item_32;
import thumb_2_misc_ops_32;

// =========================
//  Convert Instr to String
// =========================

string convert_instr_to_string(T1,T2)(T1 instr, const condition cond)
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
                	assert(0, format("Opcode unhandled: %s", op.to!string));
                }
        }
    }
    assert(0, format("Opcode unhandled: %s", op.to!string));
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
		//test_case(0xe8801ff0, "stmia.w r0, {r4, r5, r6, r7, r8, r9, sl, fp, ip}"),
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
		test_case(0xfa1ff68c, 						        	 "uxth.w r6, ip")
	];

	foreach (t; tests) {
		string actual = convert_instr_to_string!(uint,instr_32)(t.instr, t.cond);
		assert(
		    actual == t.expected,
		    format("Failed for instruction [0x%04X], got '%s'", t.instr, actual)
		);
    }
}