import std.format;

import cortex_m_core;
import thumb_2_instrs;

// =====================
//  SECURITY ATTRIBUTES
// =====================

struct s_attributes {
	// Non-secure callability
	bool nsc;
	// Security of an address
	bool ns;
	// The SAU region number
	ubyte s_region; 
	// Set to TRUE if the SAU region number is valid.
	bool sr_valid;
	// The IDAU region number.
	ubyte i_region;
	// Set to TRUE if the IDAU region number is valid.
	bool ir_valid;
}	

s_attributes security_check(const uint addr, const bool is_instr_fetech, const bool is_secure) {
	s_attributes res;

	// Setup default attributes
	// result.ns = !HaveSecurityExt();
	res.ns       = false;
	res.nsc      = false;
	res.s_region = 0;
	res.sr_valid = false;
	res.i_region = 0;
	res.ir_valid = false;

	bool idau_exempt = false;
	bool idau_ns     = true;
	bool idau_nsc    = true;

	return res;
}

// ====================
//  TT, TTT, TTA, TTAT
// ====================

// Test Target (Alternate Domain, Unprivileged). Test Target (TT) queries the Security state and access permissions
// of a memory location.

// Test Target Unprivileged (TTT) queries the Security state and access permissions of a memory location for an
// unprivileged access to that location.

// Test Target Alternate Domain (TTA) and Test Target Alternate Domain Unprivileged (TTAT) query the Security
// state and access permissions of a memory location for a Non-secure access to that location. These instructions are
// only valid when executing in Secure state, and are UNDEFINED if used from Non-secure state.

// These instructions return the Security state and access permissions in the destination register. See TT_RESP for
// the format of the destination register.

instr_32 parse_tt(const uint instr) {
	return instr_32(rd: cast(reg)slice(instr,  8, 4),
					rn: cast(reg)slice(instr, 16, 4));
}

instr_32 parse_tt_t1(const uint instr) {
	return parse_tt(instr);
}

instr_32 parse_ttt_t1(const uint instr) {
	return parse_tt(instr);
}

instr_32 parse_tta_t1(const uint instr) {
	return parse_tt(instr);
}

instr_32 parse_ttat_t1(const uint instr) {
	return parse_tt(instr);
}

uint get_tt_resp(const uint addr, bool alt, bool forceunpriv) {
	uint resp;
	immutable s_attr = security_check(addr, false, true);
	if (s_attr.sr_valid) {
		// resp.SREGION = sAttributes.sregion;
		resp |= (cast(ushort)s_attr.s_region << 8);
		// resp.SRVALID = '1';
		resp |= (1u << 17);			
	}
	if (s_attr.ir_valid) {
		// resp.IREGION = sAttributes.iregion;
		resp |= s_attr.i_region;
		// resp.IRVALID = '1';
		resp |= (1u << 23);			
	}
	return resp;
}

void 
execute_tt_t1
(vm_t)
(const ref instr_32 instr, ref vm_t vm) {
	// EncodingSpecificOperations();
	// addr = R[n];
	immutable addr = vm.get_reg(instr.rn);
	// R[d] = TTResp(addr, alt, forceunpriv);
	immutable tt_res  = get_tt_resp(addr, false, false);
	vm.set_reg(instr.rd, tt_res);
}

string convert_tt_t1_to_string(const ref instr_32 instr, const condition cond) {
	// TT{<c>}{<q>} <Rd>, <Rn>
	return format("tt%s %s, %s", get_condition_string(cond),
							     get_reg_name(instr.rd),
							     get_reg_name(instr.rn));
}


