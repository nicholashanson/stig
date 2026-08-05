package parse_elf

flags_to_u8 :: proc(a: bool, b: bool, c: bool, d: bool) -> u8 {
	return u8(u8(a) << 3 | u8(b) << 2 | u8(c) << 1 | u8(d))
}

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
	x : [32]u64,
	sp: u64,
	pc: u64,
	flags: cpu_flags,
}

get_lr :: proc(self: ^cortex_a_cpu) -> u64 {
	return self.x[30]
}

get_reg_cpu :: proc(self: ^cortex_a_cpu, r: reg, datasize: ds) -> u64 {
	if (datasize == ds._32) {
		return self.x[r] & 0xFFFF_FFFF
	} else {
		if r == reg.pc {
			return self.pc
		}
		return self.x[r]
	}
} 

set_reg_cpu :: proc(self: ^cortex_a_cpu, r: reg, val: u64, datasize: ds) {
	if r == reg.pc {
		self.pc = val
		return
	}
	self.x[r] = val
}

set_pstate_nzcv_cpu :: proc(self: ^cortex_a_cpu, nzcv: u8) {
	self.flags.n = bool(nzcv & 0x1)
	self.flags.c = bool(nzcv & 0x2)
	self.flags.z = bool(nzcv & 0x4)
	self.flags.v = bool(nzcv & 0x8)
}

// ***************************************************************************************
// *					              CORTEX A VM  										 *
// ***************************************************************************************

EL :: enum(u8) {
	EL0 = 0b00, 
	EL1 = 0b01,
	EL2 = 0b10, 
	EL3 = 0b11,
}

bit_pos :: enum(u8) {
	TBI = 20, 

	// HCR_EL2
	TGE = 27,
	E2H = 34, 

	TBID = 29,
	TBI0 = 37,
	TBI1 = 38,
	TBID0 = 51,
	TBID1 = 52,
	E0PD0 = 55,
}

sys_reg :: enum(u64) {
	// TCR_EL1, Translation Control Register (EL1)
	TCR_EL1,
	TCR_EL2,
	TCR_EL3,
	HCR_EL2,
	CurrentEL,
}

cortex_a_vm :: struct {
	cpu: cortex_a_cpu,

	APDAKeyHi_EL1 : u64, 
	APDAKeyLo_EL1 : u64,

	sys_regs: [len(sys_reg)]u64
}

get_bit :: proc(self: ^cortex_a_vm, sr: sys_reg, bp: bit_pos) -> u8 {
	return u8(slice(self.sys_regs[sr], u32(bp), 1))
} 

get_pstate_el :: proc(self: ^cortex_a_vm) -> u8 {
	return u8(slice(self.sys_regs[sys_reg.CurrentEL], 2, 2))
}

get_pc :: proc(self: ^cortex_a_vm) -> u64 {
	return get_reg(self, reg.pc)
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

set_pstate_nzcv :: proc(self: ^cortex_a_vm, nzcv: u8) {
	set_pstate_nzcv_cpu(&self.cpu, nzcv)
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