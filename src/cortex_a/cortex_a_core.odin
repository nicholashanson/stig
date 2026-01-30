package cortex_a_core

cpu_flags :: struct {
	n: bool
	z: bool
	c: bool
	v: bool
}

cortex_a_cpu :: struct {
	x : [31]u64
	sp: u64
	pc: u64

	flags: cpu_flags

	proc get_lr() -> ^u64 {
		return &self.x[30]
	}
}
