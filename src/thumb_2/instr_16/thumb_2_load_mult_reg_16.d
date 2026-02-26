import std.typecons : Tuple;
import std.format   : format;
import std.conv;
import std.algorithm;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

instr_16 parse_ldm_t1(const ushort instr) {
	// registers = ‘00000000’:register_list;
	reg[] reg_list;
	immutable reg_mask = slice(instr, 0, 8);
	foreach (i; 0 .. 8)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
    return instr_16(reg_list: reg_list,
    				rn:       cast(reg)slice(instr, 8, 3));
}

void 
execute_ldm_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	// address = R[n];
	uint rn   = vm.get_reg(instr.rn);
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	// for i = 0 to 14
	// if registers<i> == ‘1’ then
	foreach (r; regs) {
		// R[i] = MemA[address,4]; address = address + 4;
		immutable data = vm.read_word(rn);
		vm.set_reg(r, data);
		rn += 4;
	}
	// if registers<15> == ‘1’ then
	// LoadWritePC(MemA[address,4]);
	// if wback && registers<n> == ‘0’ 
	// then R[n] = R[n] + 4*BitCount(registers);
	if (!instr.reg_list.canFind(instr.rn))
		vm.set_reg(instr.rn, rn);
}

// LDM<c> <Rn>!,<registers> <Rn> not included in <registers>
// LDM<c> <Rn>,<registers>
string convert_ldm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("ldmia%s %s%s, {%s}", get_condition_string(cond),
									   	get_reg_name(instr.rn),
									   	instr.reg_list.canFind(instr.rn) ? "" : "!",
									   	get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------