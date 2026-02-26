// ***************************************************************************************
// *                                                                                     *
// *                                                                                     *
// *                                                                                     *
// *                                                                                     *
// *                                                                                     *
// *                      Data Processing (Plain Binary Immediate)                       *    
// *                                                                                     *
// *                                                                                     *
// *                                                                                     *
// *                                                                                     *
// *                                                                                     *
// ***************************************************************************************

import std.conv;
import std.format;
import std.typecons : Tuple;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// ===========
//  Parse MOV
// ===========

// MOVW<c> <Rd>,#<imm16>
// First Half-Word: [15:11] 11110, [10] i, [9:4] 100100, [3:0] imm4
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_mov_imm_t3(const uint instr) {
    immutable  imm_8 = slice(instr,  0, 8);
    immutable  imm_4 = slice(instr, 16, 4);
    immutable  imm_3 = slice(instr, 12, 3);
    immutable  i     = slice(instr, 26, 1);
    const uint imm   = (imm_4 << 12) | (i << 11) | (imm_3 << 8) | imm_8;
    return instr_32(rd:  cast(reg )slice(instr,  8, 4),
                    imm: imm);
}

void 
execute_mov_imm_t3
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
    vm.set_reg(instr.rd, instr.imm);
}

string convert_mov_imm_t3_to_string(const ref instr_32 instr, const condition cond) {
    return format("mov%s.w %s, #%d", get_condition_string(cond), get_reg_name(instr.rd), instr.imm);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       BFC                                           *
// ***************************************************************************************
// Bit Field Clear clears any number of adjacent bits at any position in a register, 
// without affecting the other bits in the register.

// ===========
//  Parse BFC
// ===========

// BFC<c> <Rd>,#<lsb>,#<width>
// First Half-Word: [15:0] 1111001101101111 
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5] 0, [4:0] msb
instr_32 parse_bfc_t1(uint instr) {
    immutable imm_2 = slice(instr,  6, 2);
    immutable imm_3 = slice(instr, 12, 3);
    return instr_32(msb: slice(instr,  0, 5),
                    lsb: (imm_3 << 2) | imm_2,
                    rd:  cast(reg)slice(instr, 8, 4));
}

// =============
//  Execute BFC
// =============

void 
execute_bfc_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
    immutable lsb = instr.lsb;
    immutable msb = instr.msb;
    uint      res = vm.get_reg(instr.rd);
    if (msb >= lsb) {
        uint width = msb - lsb + 1;
        uint field_mask = ((1u << width) - 1u) << lsb;
        res &= ~field_mask;
    }
    vm.set_reg(instr.rd, res);
}

string convert_bfc_t1_to_string(const ref instr_32 instr, const condition cond) {
    return format("bfc%s %s, #%d, #%d", cond != condition.none ? cond.to!string : "", 
                                        get_reg_name(instr.rd),
                                        instr.lsb, instr.msb - instr.lsb + 1);
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       BFI                                           *
// ***************************************************************************************

// ===========
//  Parse BFI
// ===========

// BFI<c> <Rd>,<Rn>,#<lsb>,#<width>
// [15:4] 111100110110, [3:0] Rn
// [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm2, [5] 0, [4:0] msb
instr_32 parse_bfi_t1(const uint instr) {
    immutable imm_2 = slice(instr,  6, 2);
    immutable imm_3 = slice(instr, 12, 3);
    return instr_32(msb: slice(instr,  0, 5),
                    lsb: (imm_3 << 2) | imm_2,
                    rd:  cast(reg)slice(instr,  8, 4),
                    rn:  cast(reg)slice(instr, 16, 4));
}

// =============
//  Execute BFI
// =============

void 
execute_bfi_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
    immutable  lsb   = instr.lsb;
    const uint width = (instr.msb >= instr.lsb) ? instr.msb - instr.lsb + 1 : 0;
    auto       res   = vm.get_reg(instr.rd);
    immutable  rn    = vm.get_reg(instr.rn);
    if (width > 0 && lsb < 32 && (lsb + width) <= 32) {
        uint field_mask  = ((1u << width) - 1u) << lsb;
        uint insert_bits = (rn & ((1u << width) - 1u)) << lsb;
        res = (res & ~field_mask) | insert_bits;
    }
    vm.set_reg(instr.rd, res);
}

// BFI<c> <Rd>,<Rn>,#<lsb>,#<width>
string convert_bfi_t1_to_string(const ref instr_32 instr, const condition cond) {
    return format("bfi%s %s, %s%s%s", get_condition_string(cond),
                                      get_reg_name(instr.rd),
                                      get_reg_name(instr.rn),
                                      get_imm_string(instr.lsb),
                                      get_imm_string(instr.msb - instr.lsb + 1));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       ADD                                           *
// ***************************************************************************************

// ===========
//  Parse ADD
// ===========

// ADDW<c> <Rd>,<Rn>,#<imm12>
// First Half-Word: [15:11] 11110, [10] i, [9:4] 100000, [3:0] Rn 
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8
instr_32 parse_add_imm_t4(const uint instr) {
    immutable  imm_8 = slice(instr,  0, 8);
    immutable  imm_3 = slice(instr, 12, 3);
    immutable  i     = slice(instr, 26, 1);
    // imm32 = ZeroExtend(i:imm3:imm8, 32);
    const uint imm   = (i << 11) | (imm_3 << 8) | imm_8; 
    return instr_32(rd:  cast(reg )slice(instr,  8, 4),
                    rn:  cast(reg )slice(instr, 16, 4),
                    imm: imm);
    // setflags = FALSE;
}

// ========================
//  Execute ADD(Immediate)
// ========================

void 
execute_add_imm_t4
(vm_t)
(const instr_32 instr, ref vm_t vm) {
    immutable rn  = vm.get_reg(instr.rn);
    immutable imm = instr.imm;
    // (result, carry, overflow) = AddWithCarry(R[n], imm32, ‘0’);
    immutable res = add_with_carry(rn, imm, false);
    if (instr.set_flags) {
        vm.set_n(res.result);            // APSR.N = result<31>;
        vm.set_z(res.result);            // APSR.Z = IsZeroBit(result);
        vm.set_c(res.carry);             // APSR.C = carry;
        vm.set_v(res.overflow);          // APSR.V = overflow;
    }
    vm.set_reg(instr.rd, res.result);
}

// ADDW<c> <Rd>,<Rn>,#<imm12>
string convert_add_imm_t4_to_string(const ref instr_32 instr, const condition cond) {
    return format("addw%s %s, %s%s", get_condition_string(cond),
                                     get_reg_name(instr.rd),
                                     get_reg_name(instr.rn),
                                     get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       UBFX                                          *
// ***************************************************************************************
// Unsigned Bit Field Extract extracts any number of adjacent bits at any position from 
// one register, zero extends them to 32 bits, and writes the result to the destination 
// register.

// ============
//  Parse UBFX
// ============

// UBFX <Rd>, <Rn>, #<lsb>, #<width>
// First Half-Word: [15:4] 111100111100, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:6] imm3, [5] 0, [4:0] widthm1
instr_32 parse_ubfx_t1(const uint instr) {
    immutable imm_2 = slice(instr,  6, 2);
    immutable imm_3 = slice(instr, 12, 3);
    return instr_32(widthm1: slice(instr,  0, 5), // widthminus1 = UInt(widthm1);
                    rd:      cast(reg)slice(instr,  8, 4),
                    rn:      cast(reg)slice(instr, 16, 4),
                    lsb:     (imm_3 << 2) | imm_2);
}

// ==============
//  Execute UBFX
// ==============

void 
execute_ubfx_t1
(vm_t)
(const instr_32 instr, ref vm_t vm) {
    const uint msb     = instr.lsb + instr.widthm1;
    const uint lsb     = instr.lsb;
    const uint widthm1 = instr.widthm1;
    immutable  rn      = vm.get_reg(instr.rn);
    if (msb < 32) {
        immutable res = slice(rn, lsb, widthm1 + 1);
        vm.set_reg(instr.rd, res);
    }
}

string convert_ubfx_t1_to_string(const ref instr_32 instr, const condition cond) {
    return format("ubfx %s, %s, #%d, #%d", get_reg_name(instr.rd), get_reg_name(instr.rn),
                                           instr.lsb, instr.widthm1 + 1);
}
// ---------------------------------------------------------------------------------------

// ======================
//  Parse SUB(Immediate)
// ======================

// SUBW<c> <Rd>,<Rn>,#<imm12>
// First Half-Word: [15:11] 11110, [10] i, [9:5] 01101, [4] S, [3:0] Rn
// Second Half-Word: [15] 0, [14:12] imm3, [11:8] Rd, [7:0] imm8 
instr_32 parse_sub_imm_t4(const uint instr) {
    immutable imm_8 = slice(instr,  0, 8);
    immutable imm_3 = slice(instr, 12, 3);
    immutable i     = slice(instr, 26, 1);
    const uint imm  = (i << 11) | (imm_3 << 8) | imm_8; // imm32 = ZeroExtend(i:imm3:imm8, 32);
    return instr_32(rd:  cast(reg)slice(instr,  8, 4),
                    rn:  cast(reg)slice(instr, 16, 4),
                    imm: imm);
    // setflags = FALSE;
}

// =========================
//  Executre SUB(Immediate)
// =========================

void 
execute_sub_imm_t4
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
    immutable rn  = vm.get_reg(instr.rn);
    immutable imm = instr.imm;
    // (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), ‘1’);
    immutable res = add_with_carry(rn, ~imm, true);
    if (instr.set_flags) {
        vm.set_n(res.result);       // APSR.N = result<31>;
        vm.set_z(res.result);       // APSR.Z = IsZeroBit(result);
        vm.set_c(res.carry);        // APSR.C = carry;
        vm.set_v(res.overflow);     // APSR.V = overflow;
    }
    vm.set_reg(instr.rd, res.result);
}

// SUBW<c> <Rd>,<Rn>,#<imm12>
string convert_sub_imm_t4_to_string(const ref instr_32 instr, const condition cond) {
    return format("subw%s %s, %s%s", get_condition_string(cond),
                                     get_reg_name(instr.rd),
                                     get_reg_name(instr.rn),
                                     get_imm_string(instr.imm));
}
// ---------------------------------------------------------------------------------------

// ***************************************************************************************
// *                                       SBFX                                          *
// ***************************************************************************************

// ============
//  Parse SBFX
// ============

// SBFX<c> <Rd>,<Rn>,#<lsb>,#<width>
// [111100110100], [3:0] Rn
// [0], [14:12] imm3, [11:8] Rd, [7:6] imm2, [0] 5, [4:0] widthm1
instr_32 parse_sbfx_t1(const uint instr) {
    immutable imm_2 = slice(instr,  6, 2);
    immutable imm_3 = slice(instr, 12, 3);
    return instr_32(widthm1: slice(instr,  0, 5), // widthminus1 = UInt(widthm1);
                    rd:      cast(reg)slice(instr,  8, 4),
                    rn:      cast(reg)slice(instr, 16, 4),
                    lsb:     (imm_3 << 2) | imm_2);
}

// ==============
//  Execute SBFX
// ==============

void 
execute_sbfx_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
    // EncodingSpecificOperations();
    // msbit = lsbit + widthminus1;
    const uint widthm1 = instr.widthm1;
    const uint msb     = instr.lsb + widthm1;
    const uint lsb     = instr.lsb;
    const uint width   = widthm1 + 1;
    uint       rn      = vm.get_reg(instr.rn);
    // if msbit <= 31 then
    if (msb < 32) {
        // R[d] = SignExtend(R[n]<msbit:lsbit>, 32);
        uint res = slice(rn, lsb, width);
        if (slice(res, widthm1, 1) == 1) {
            res |= ~((1u << width) - 1);
        }
        vm.set_reg(instr.rd, res);
    }
    // else
    // UNPREDICTABLE;
}

// SBFX<c> <Rd>,<Rn>,#<lsb>,#<width>
string convert_sbfx_t1_to_string(const ref instr_32 instr, const condition cond) {
    return format("sbfx%s %s, %s, #%d, #%d", get_condition_string(cond),
                                             get_reg_name(instr.rd),
                                             get_reg_name(instr.rn),
                                             instr.lsb, instr.widthm1 + 1);
}
// ---------------------------------------------------------------------------------------