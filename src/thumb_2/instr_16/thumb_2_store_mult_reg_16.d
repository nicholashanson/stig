import std.typecons : Tuple;
import std.format   : format;
import std.conv;
import std.algorithm;

import thumb_2_opcodes;
import thumb_2_instrs;
import cortex_m_core;

// STM<c> <Rn>!,<registers>
instr_16 parse_stm_t1(const ushort instr) {
	// registers = ‘00000000’:register_list;
	// wback = TRUE;
	reg[] reg_list;
	immutable reg_mask = slice(instr, 0, 8);
	foreach (i; 0 .. 8)
    	if (reg_mask & (1 << i))
        	reg_list ~= cast(reg)i;
    return instr_16(reg_list: reg_list,
    				rn:       cast(reg)slice(instr, 8, 3));
}

void 
execute_stm_t1
(vm_t)
(const ref instr_16 instr, ref vm_t vm) {
	auto regs = instr.reg_list.dup; 
	regs.sort!((a,b) => cast(int)a < cast(int)b);
	// address = R[n];
	uint rn   = vm.get_reg(instr.rn);
	// for i = 0 to 14
	// if registers<i> == ‘1’ then
	foreach (r; regs) {
		immutable data = vm.get_reg(r);
		// MemA[address,4] = R[i];
		// address = address + 4;
		vm.write_word(rn, data);
		if (instr.rn == reg.sp)
			vm.log_push(rn, data);
		rn += 4;
	}
	// if wback then R[n] = R[n] + 4*BitCount(registers);
	// wback = TRUE;
	vm.set_reg(instr.rn, rn);
}

// STM<c> <Rn>!,<registers>
string convert_stm_t1_to_string(const ref instr_16 instr, const condition cond) {
	return format("stmia%s %s!, {%s}", get_condition_string(cond),
									   get_reg_name(instr.rn),
									   get_reg_list_string(instr.reg_list));
}
// ---------------------------------------------------------------------------------------