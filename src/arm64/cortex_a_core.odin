package parse_elf

cpu_flags :: struct {
	n: bool,
	z: bool,
	c: bool,
	v: bool
}

acc_type :: enum(u8) {
	normal,
}

// ***************************************************************************************
// *					              CORTEX A CPU  									 *
// ***************************************************************************************

cortex_a_cpu :: struct {
	x : [31]u64,
	sp: u64,
	pc: u64,
	flags: cpu_flags
}

get_lr :: proc(self: ^cortex_a_cpu) -> u64 {
	return self.x[30]
}

get_reg_cpu :: proc(self: ^cortex_a_cpu, r: reg, datasize: ds) -> u64 {
	if (datasize == ds._32) {
		return self.x[r] & 0xFFFF_FFFF
	} else {
		return self.x[r]
	}
} 

set_reg_cpu :: proc(self: ^cortex_a_cpu, r: reg, val: u64, datasize: ds) {
	self.x[r] = val
}

// ***************************************************************************************
// *					              CORTEX A VM  										 *
// ***************************************************************************************

cortex_a_vm :: struct {
	cpu: cortex_a_cpu
}

get_reg :: proc(self: ^cortex_a_vm, r: reg, datasize: ds = ds._64) -> u64 {
	return get_reg_cpu(&self.cpu, r, datasize)
} 

set_reg :: proc(self: ^cortex_a_vm, r: reg, val: u64, datasize: ds = ds._64) {
	set_reg_cpu(&self.cpu, r, val, datasize)
}

set_sp :: proc(self: ^cortex_a_vm, val: u64) {
	set_reg(self, reg.x31, val)
}

has_lse2_ext :: proc(self: ^cortex_a_vm) -> bool {
	return false
}

write :: proc(self: ^cortex_a_vm, addr: u64, dbytes: u8, acc: acc_type, data: $T, be: bool = false) {
	return
}

read :: proc(self: ^cortex_a_vm, addr: u64, dbytes: u8, acc: acc_type) -> u64 {
	return 0
}