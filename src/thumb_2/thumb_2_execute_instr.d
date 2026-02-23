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

void 
execute_instr
(vm_t,t)
(const t instr, ref vm_t vm) {
    bool handled = false;

    foreach (member; __traits(allMembers, opcode))
    {
        enum op = mixin("opcode." ~ member);

        if (instr.op == op)
        {
            static if (__traits(compiles, mixin("execute_" ~ member)))
            {
                alias Handler = mixin("execute_" ~ member);
                alias P = Parameters!(Handler!(vm_t));
                pragma(msg, "Handler execute_" ~ member ~ " signature:");
                foreach (i, T; P) {
                     pragma(msg, "  param " ~ i.stringof ~ ": " ~ T.stringof);
                pragma(msg, "  returns: " ~ ReturnType!(Handler!(vm_t)).stringof);
                }
                static if (__traits(compiles, Handler!(vm_t)(instr, vm)))
                {
                    pragma(msg, "Handler callable with this instruction type: execute_" ~ member);
                    Handler!(vm_t)(instr, vm);
                    handled = true;
                    break;
                }
                else
                {
                    pragma(msg, "Handler exists but wrong signature: execute_" ~ member);
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

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

string cpu_diff(const ref cortex_m_cpu a, const ref cortex_m_cpu b)
{
    auto buf = appender!string();

    // -------- Registers --------
    foreach (i; 0 .. 16)
    {
        auto ra = a.core_registers[i];
        auto rb = b.core_registers[i];

        if (ra != rb)
            buf ~= format("r%-2d : 0x%08X vs 0x%08X\n", i, ra, rb);
    }

    // -------- Stack pointers --------
    if (a.get_sp() != b.get_sp())
        buf ~= format("sp  : 0x%08X vs 0x%08X\n", a.get_sp(), b.get_sp());

    if (a.get_pc() != b.get_pc())
        buf ~= format("pc  : 0x%08X vs 0x%08X\n", a.get_pc(), b.get_pc());

    // -------- Flags --------
    if (a.n != b.n) buf ~= format("N   : %s vs %s\n", a.n, b.n);
    if (a.z != b.z) buf ~= format("Z   : %s vs %s\n", a.z, b.z);
    if (a.c != b.c) buf ~= format("C   : %s vs %s\n", a.c, b.c);
    if (a.v != b.v) buf ~= format("V   : %s vs %s\n", a.v, b.v);

    return buf.data;
}

// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

cortex_m_cpu make_cpu(T...)(T args)
{
    cortex_m_cpu cpu;

    foreach (arg; args)
    {
        static if (is(typeof(arg[0]) == reg))
            cpu.set_reg(arg[0], arg[1]);
        static if (is(typeof(arg[0]) == flag))
            cpu.set_flag(arg[0], arg[1]);
    }

    return cpu;
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
    ];

    foreach (t; tests) {
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
    //test_case(0xe7cf, 
    //      instr_16(op: opcode.b_n,                    imm_long: 0xffffffcf),
    //      cortex_m_cpu(pc: 10, r3: 1),
    //      cortex_m_cpu(pc: 18, r3: 1))
    //test_case(0x469d, 
    //        instr_16(op: opcode.mov_reg_t2,    rd: reg.sp,  rm: reg.r3),
    //        test_vm(cpu: make_cpu(tuple(msp, 10), r3: 1),
    //      cortex_m_cpu(pc: 2, msp: 1,  r3: 1)),
    //test_case(0x460f, 
    //      instr_16(op: opcode.mov_reg_t1,        rd: reg.r7,  rm: reg.r1),
    //      test_vm(cpu: make_cpu(tuple(reg.r7, 10), tuple(reg.r1, 1))),
    //      test_vm(cpu: make_cpu(tuple(reg.pc,  2), tuple(reg.r7, 1), tuple(reg.r1, 1)))),
    
    test_case(0x4798, 
          instr_16(op: opcode.blx_t1,           rm: reg.r3),
          test_vm(cpu: make_cpu(tuple(reg.pc, 10), tuple(reg.r3, 20))),
          test_vm(cpu: make_cpu(tuple(reg.pc, 20), tuple(reg.lr, 12), tuple(reg.r3, 20)))),
    //test_case(0xaf00, 
    //      instr_16(op: opcode.add_sp_t1,        rd: reg.r7,         imm: 0),
     //     cortex_m_cpu(msp: 10, r7: 20),
      //    cortex_m_cpu(pc: 2, msp: 10, r7: 10)),
       
    //test_case(0xb092, 
     //       instr_16(op: opcode.sub_sp,                 imm: 72),
      //      cortex_m_cpu(msp: 90),
       //   cortex_m_cpu(pc: 2, msp: 18)),

    
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
          test_vm(cpu: make_cpu(tuple(reg.r2, 10), tuple(reg.pc, 10))),
          test_vm(cpu: make_cpu(tuple(reg.r2, 14), tuple(reg.pc, 12)))),
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

    //test_case(0x4652, 
    //        instr_16(op: opcode.mov_reg_t2,    rd: reg.r2,  rm: reg.r10),
    //        test_vm(cpu: make_cpu(tuple(reg.r2, 1), tuple(reg.r10, 3))),
    //        test_vm(cpu: make_cpu(tuple(reg.pc, 2), tuple(reg.r2,  3), tuple(reg.r10, 3)))),
                 /*

    test_case(0x9300, 
            instr_16(op: opcode.str_sp,    rt: reg.r3,        imm: 0),
            cortex_m_cpu(r2: 1, r10: 3),
            cortex_m_cpu(r2: 3, r10: 3))

    test_case(0x458c, 
            instr_16(op: opcode.cmp_high_1,    rn: reg.r12, rm: reg.r1),
            cortex_m_cpu(r3: 0, r0: 0),
            cortex_m_cpu(pc: 2, z: true, n: false, c: true, v: false)),
    
    
    

    test_case(0x4241, 
            instr_16(op: opcode.negs,      rd: reg.r1,  rn: reg.r0),
          cortex_m_cpu(r0: 1),
            cortex_m_cpu(pc: 2, r1: -1, r0: 1)),

    
    */ ];

    foreach (t; tests) {
        execute_instr(t.instr, t.before);
        assert(
            t.before == t.expected,
            format("Failed for instruction 0x%08X: %s", t.instr_bytes, cpu_diff(t.before.cpu, t.expected.cpu))
        );
    }
}


