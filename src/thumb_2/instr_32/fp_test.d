import std.format;

import thumb_2_instrs;

import helium;
import cortex_m_core;
import vm;

unittest {
  unpacked_fp expected = unpacked_fp(fpt: fp_type.zero, sign_bit: false, val: 0);
  tiny_vm vm;
  uint fpval    = 0x0040_0000;
  bool predicated = false;
  SET_FPSCR_FZ(vm);
  assert(FPSCR_FZ_SET(vm));
  auto fpscr_val  = vm.get_fpscr();
  assert(cast(bool)slice(fpscr_val, 24, 1));
  auto res = fp_unpack_base!(uint,32)(fpval, fpscr_val, predicated, vm);
  assert(res.fpt      == expected.fpt,      "Actual result does not match expected fpt");
  assert(res.sign_bit == expected.sign_bit, "Actual result does not match expected sign_bit");
  assert(res.val      == expected.val,      format("Actual result does not match expected val: %f", res.val));
  assert(FPSCR_IDC_SET(vm), "FPSCR_IDC was not set correctly");
}