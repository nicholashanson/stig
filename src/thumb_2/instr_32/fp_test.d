import std.format;
import std.typecons : Tuple, tuple;

import thumb_2_instrs;
import thumb_2_execute_instr;

import helium;
import cortex_m_core;
import vm;
import ra81d;

// ***************************************************************************************
// *                                   FP UNPACK BASE                                    *
// ***************************************************************************************

void cmp_unpacked_fp(unpacked_fp actual, unpacked_fp expected) {
  assert(actual.fpt      == expected.fpt,      "Actual result does not match expected fpt");
  assert(actual.sign_bit == expected.sign_bit, "Actual result does not match expected sign_bit");
  assert(actual.val      == expected.val,      format("Actual result does not match expected val: %f", actual.val));
}

unittest {

  // ========
  //  32 BIT
  // ========

  // flush to zero
  {
    unpacked_fp expected = unpacked_fp(fpt: fp_type.zero, sign_bit: false, val: 0);
    tiny_vm vm;
    uint fpval      = 0x0040_0000;
    bool predicated = false;
    SET_FPSCR_FZ(vm);
    assert(FPSCR_FZ_SET(vm));
    auto fpscr_val  = vm.get_fpscr();
    assert(cast(bool)slice(fpscr_val, 24, 1));
    auto res = fp_unpack_base!(uint,32)(fpval, fpscr_val, predicated, vm);
    cmp_unpacked_fp(res, expected);
    assert(FPSCR_IDC_SET(vm), "FPSCR_IDC was not set correctly");
  }

  // subnoraml value 
  {
    unpacked_fp expected = unpacked_fp(fpt: fp_type.non_zero, sign_bit: false, val: 2.0 ^^ -127);
    tiny_vm vm;
    uint fpval      = 0x0040_0000;
    bool predicated = false;
    auto fpscr_val  = vm.get_fpscr();
    auto res        = fp_unpack_base!(uint,32)(fpval, fpscr_val, predicated, vm);
    cmp_unpacked_fp(res, expected);
  }
}

unittest {
  cortex_m_vm!ra8d1_mem vm;
  auto res = is_cp_enabled(0, true, true, vm);
  assert(!res[0]);

  auto x = fp_round_base!(float,float,32)(1.0, 0, false, vm);
}

// ***************************************************************************************
// *                                   FP MAX NORMAL                                     *
// ***************************************************************************************

unittest {
  assert(fp_max_normal!(ushort,16)(false) == 0x7BFF);
  assert(fp_max_normal!(ushort,16)(true) == 0xFBFF);

  assert(fp_max_normal!(uint,32)(false) == 0x7F7FFFFF);
  assert(fp_max_normal!(uint,32)(true) == 0xFF7FFFFF);

  assert(fp_max_normal!(ulong,64)(false) == 0x7FEFFFFFFFFFFFFFUL);
  assert(fp_max_normal!(ulong,64)(true) == 0xFFEFFFFFFFFFFFFFUL);
}

// ***************************************************************************************
// *                                   FP INFINITY                                       *
// ***************************************************************************************

unittest {
  assert(fp_infinity!(ushort,16)(false) == 0x7C00);
}

unittest {
  cortex_m_vm!ra8d1_mem vm;
  auto x = fp_add!(float,uint,32)(1.0, 2.0, true, true, vm);
}