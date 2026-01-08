I am Stig of the Hexadecimal Dump. Feed me objdump files and I will make them execute.

<div align="center">
  <img src="assets/logo.png" width="200"><br>
</div>

# Cortex-M
## Thumb-2
Cortex-M always runs in Thumb-2 mode. 
### Opcodes
| Column 1 | Column 2 | Column 3 | Column 4 |
|---------|----------|----------|----------|
| adc_imm_32 | adc_reg_32 | add_32 | add_imm_32 |
| add_reg_32 | adr_32 | and_reg_32 | asr_imm_32 |
| asr_reg_32 | b_32 | b_cond_32 | b_uncond_32 |
| bfc_32 | bfi_32 | bic_imm_32 | bic_reg_32 |
| bl_32 | clz_32 | cmn_32 | cmn_imm_32 |
| cmn_reg_32 | cmp_imm_32 | cmp_reg_32 | dmb_32 |
| dsb_32 | eor_imm_32 | isb_32 | ldh_32 |
| ldmdb_32 | ldmia_32 | ldr_imm_32 | ldr_lit_32 |
| ldr_reg_32 | ldr_sh_32 | ldrbt_32 | ldrd_imm_32 |
| ldrsb_32 | ldrsbt_32 | ldrt_32 | ldrb_32 |
| lsl_imm_32 | lsl_reg_32 | lsr_imm_32 | lsr_reg_32 |
| mla_32 | mls_32 | mov_reg_32 | movt_32 |
| mrs_32 | msr_32 | mul_32 | mvn_imm_32 |
| mvn_reg_32 | nop_32 | orn_32 | orn_imm_32 |
| orn_reg_32 | orr_32 | orr_imm_32 | orr_reg_32 |
| pld_32 | pop_mult_reg_32 | push_mult_reg_32 | qadd_32 |
| qdadd_32 | qdsub_32 | qsub_32 | rbit_32 |
| rev_16_32 | rev_32 | revsh_32 | ror_32 |
| ror_imm_32 | rrx_32 | sbc_imm_32 | sbc_reg_32 |
| sbfx_32 | sel_32 | stmb_32 | stmia_32 |
| str_reg_32 | strd_32 | sub_imm_32 | sub_reg_32 |
| sxtab_16_32 | sxtab_32 | sxtah_32 | sxtb16_32 |
| sxtb_32 | teq_imm_32 | tst_imm_32 | tst_reg_32 |
| uadd8_32 | ubfx_32 | udiv_32 | umull_32 |
| uxtab_16_32 | uxtab_32 | uxtah_32 | uxtb16_32 |
| uxtb_32 | uxth_32 |  |  |


### Instructions
Thumb-2 instructions can be either 16 or 32-bit. These are modelled in Strig like this:
```code
struct instr_16 {
	uint addr;
	opcode op;
	reg rd;
	reg rm;
	reg rn;
    reg rm;
	reg rt;
	uint imm;
	int offset;
	condition cond;
	reg[] reg_list = null;
	bool set_flags;
	ubyte first_cond;
	ubyte mask;
	bool enable;
	bool affect_pri;
	bool affect_fault;
}
```
- **addr:** every instruction has an address that is loaded into the program counter
- **opcode:** every instruction has an opcode that identifes its type
- **rd:** destination register
- **rn:** first source register
- **rm:** second source register
- **imm:** immediate value
- **offet:** used in jumps/branches
- **rt:** target register, used in load and store operations. In the case of store, it holds the value to be stored, in the case of load, it recieves the loaded value
- **cond:** condition used in branching
- **reg_list:** used in push and pop of multiple registers
- **first_cond/mask:** used in the if-then instruction only
- **enable/affet_pri/affect_fault:** used in the cps insturciton only

```code
struct instr_32 {
	opcode op;
	reg rd;
	reg rn;
	reg rm;
	reg rt;
	shift_type shift_t;
	uint imm;
	ubyte shift_n;
	int offset;
	reg[] reg_list;
	uint ls_bit;
	uint width;
	uint ms_bit;
	reg rd_hi;
	reg rd_lo;
	reg rt_2;
	reg ra;
	condition cond;
	bool wback;
	bool add;
	bool index;
	ubyte mask;
	special_reg spec_reg;
	bool set_flags;
}
```
- **shift_t:** used in bit-shifts or rotations to denote the type of bit-shift or rotation
- **shift_n:** the number of bit positions to shift or rotate
- **ls_bit/ms_bit/width:** used in **unsigned bit-field extract** and **bit-field clear**
- **rd_hi/rd_lo:** used in instructions that need two destination registers (eg multiply)
- **ra:** used in **multiply-accumulate** and **multiply-subtract** to store the addend
- **wback:** true if the address of a load or store should be written back to the target register
- **add:** true if the immediate in a load or store should be added to the base address to derive the offset address, false if it should be subracted
- **index:** false if the immediate in a load or store is disregarded when calculating the offset address
- **spec_reg**: used in the **msr** and **mrs** insturctions to denote the special register to be read or written to
- **set_flags**: true if the result of the operation should affect CPU flags
