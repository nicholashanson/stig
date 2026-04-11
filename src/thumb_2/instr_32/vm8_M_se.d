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


