import std.format;

import thumb_2_instrs;

import helium;
import cortex_m_core;
import vm;

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
    uint fpval    = 0x0040_0000;
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
    uint fpval    = 0x0040_0000;
    bool predicated = false;
    auto fpscr_val  = vm.get_fpscr();
    auto res = fp_unpack_base!(uint,32)(fpval, fpscr_val, predicated, vm);
    cmp_unpacked_fp(res, expected);
  }
}