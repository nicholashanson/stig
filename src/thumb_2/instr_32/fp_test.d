import helium;
import cortex_m_core;
import vm;

unittest {
  unpacked_fp expected = unpacked_fp(fpt: fp_type.zero, sign_bit: false, val: 0);
  tiny_vm vm;
  uint fpval    = 0x0040_0000;
  bool predicated = false;
  FPSCR_FZ_SET(vm);
  auto fpscr_val  = vm.get_fpscr_val();
  auto res = fp_unpack_base(fpval, fpscr_val, predicated);
  assert(res == expected);
  assert(FPSCR_IDC_SET(vm));
}