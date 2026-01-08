I am Stig of the Hexadecimal Dump. Feed me objdump files and I will make them execute.

<div align="center">
  <img src="assets/logo.png" width="200"><br>
</div>

# Cortex-M
## Thumb-2
Cortex-M always runs in Thumb-2 mode. Thumb-2 instructions can be either 16 or 32-bit. These are modelled in Strig like this:
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
**struct** instr_32 {
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
