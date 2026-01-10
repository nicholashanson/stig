import thumb_2_opcodes;
import cortex_m_core;

struct instr_16 {
	uint addr;
	opcode op;
	reg rd;
	reg rm;
	reg rn;
	reg rt;
	uint imm;
	int offset;
	int imm_long;
	condition cond;
	reg[] reg_list = null;
	bool set_flags;
	ubyte first_cond;
	ubyte mask;
	bool enable;
	bool affect_pri;
	bool affect_fault;
}