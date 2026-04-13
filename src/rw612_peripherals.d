import rw612_defs;

uint[rw612_peripheral_reg] rw612_peripheral_regs = [
	SYS_RST_EN: 0x0,
	CAU_SLP_CTRL: 0x0000_0002,

	PLL_CTRL: 0x0002_9D00,
	SOURCE_CLK_GATE: 0x0000_00FF,
	CLKTREE_CTRL_SIX_REG: 0,
];