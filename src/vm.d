import std.format;
import std.algorithm;
import std.stdio;
import std.range;
import std.traits : isIntegral;

import log;
import parse_elf;
import cortex_m_core;
import memory_sections;
import thumb_2_instrs;
import thumb_2_decode_instr;
import thumb_2_execute_instr;

struct dummy_mem {
	enum flash_origin = 0;
	enum flash_length = 0;
	enum ram_origin = 0;
	enum ram_length = 0;
    void write_word(size_t addr, uint val) {}
    uint read_word(size_t addr) { return 0; }
    void write_byte(size_t addr, ubyte val) {}
    ubyte read_byte(size_t addr) { return 0; }
    void write_half_word(size_t addr, ushort val) {}
    ushort read_half_word(size_t addr) { return 0; }
    void flip_bit(const uint addr, const uint bit) {}
    string get_reg_name(const uint addr) { return ""; }
}

alias test_vm = cortex_m_vm!(dummy_mem);
alias tiny_vm = cortex_m_vm!(tiny_mem);
alias stm32f4_vm = cortex_m_vm!(stm32f4_mem);

struct cortex_m_vm(mem_t) {
	cortex_m_cpu cpu;
	mem_t mem;
	addr_instr[] current_program;
	string[] func_names;
	st_name_val[] objects;

	// ----------------------------------------- PC ----------------------------------------- 
	private bool pc_modified;

	uint get_pc() const {
		return cpu.get_pc();
	}

	bool check_pc_modified() {
		bool res = pc_modified;
		pc_modified = false;
		return res;
	}

	void increment_pc(const uint val) {
		cpu.increment_pc(val);
	}

	void clear_thumb_bit() {
		cpu.clear_thumb_bit();
	}

	void init_pc(const uint v) {
		cpu.set_reg(reg.pc, v);
	}

	void align_pc() {
		cpu.align_pc();
	}

	bool in_it_block() {
		return cpu.in_it_block();
	}

	exception get_current_exception() {
		return cpu.current_exception;
	}

	void set_current_exception(const exception exc) {
		cpu.current_exception = exc;
	}

	uint get_xpsr() {
		return cpu.get_xpsr();
	}

	void set_npriv(const bool v) {
		cpu.npriv = v;
	}

	bool get_sp_sel() const {
		return cpu.sp_sel;
	}

	void set_sp_sel(bool v) {
		cpu.sp_sel = v;
	}

	uint get_sp() {
		return cpu.get_sp();
	}

	void set_xpsr(const uint v) {
		cpu.set_xpsr(v);
	}
	// --------------------------------------------------------------------------------------

	// ---------------------------------------- Flags ---------------------------------------
	bool get_c() {
		return cpu.c;
	}

	void set_c(t)(const t v) {
		cpu.set_c(v);
	}

	bool get_v() {
		return cpu.get_v();
	}

	void set_v(t)(const t v) {
		cpu.set_v(v);
	}

	void set_n(t)(const t v) {
		cpu.set_n(v);
	}

	bool get_n() {
		return cpu.get_n();
	}

	bool get_z() {
		return cpu.get_z();
	}
 
	void set_z(t)(t v) if (isIntegral!t) {
    	cpu.set_z(v);
	}

	bool get_ge0() {
		return cpu.ge0;
	}

	bool get_ge1() {
		return cpu.ge1;
	}

	bool get_ge2() {
		return cpu.ge2;
	}

	bool get_ge3() {
		return cpu.ge3;
	}

	void set_ge0(const bool v) {
		cpu.ge0 = v;
	}

	void set_ge1(const bool v) {
		cpu.ge1 = v;
	}

	void set_ge2(const bool v) {
		cpu.ge2 = v;
	}

	void set_ge3(const bool v) {
		cpu.ge3 = v;
	}

	void set_q(const bool v) {
		cpu.q = v;
	}

	bool get_fault_mask() {
		return cpu.fault_mask;
	}

	bool get_npriv() {
		return cpu.npriv;
	}

	void set_npriv(bool v) {
		cpu.npriv = v;
	}

	bool get_pri_mask() {
		return cpu.pri_mask;
	}

	void set_it_block(const xyz it_block) {
		cpu.it_block = it_block;
	}

	void init_it_block_stack(const condition cond) {
		cpu.init_it_block_stack(cond);
	}

	auto get_it_block_stack() {
		return cpu.it_block_stack;
	}

	bool it_block_stack_empty() {
		return cpu.it_block_stack.empty;
	}

	bool it_condition_is_met(T)() {
	  condition active_cond = cpu.it_block_stack.back;
      cpu.it_block_stack.removeBack();
      if (!condition_is_met(active_cond, cpu)) {
        static if (is(T == instr_16))
        	increment_pc(2);
        else static if (is(T == instr_32))
        	increment_pc(4);
    	else
        	static assert(0, "Unknown instruction type");
        return false;
      } else {
      	return true;
      }
	}

	ubyte get_basepri() {
		return cpu.basepri;
	}

	void set_basepri(const ubyte v) {
		cpu.basepri = v;
	}

	uint get_psp() {
		return cpu.psp;
	}

	void set_psp(const uint v) {
		cpu.psp = v;
	}

	uint get_msp() {
		return cpu.msp;
	}

	void set_msp(const uint v) {
		cpu.msp = v;
	}

	void set_fpscr(const uint v) {
		cpu.set_fpscr(v);
	}

	// --------------------------------------------------------------------------------------

	// -------------------------------------------------------------------------------------- 
	uint get_reg(const reg r) const {
		return cpu.get_reg(r);
	}

	void set_reg(const reg r, const uint val) {
		if (r == reg.pc) 
			pc_modified = true;
		cpu.set_reg(r, val);
	} 
	// ---------------------------------------- Memory --------------------------------------
	void write_half_word(const size_t addr, const ushort val) {
		mem.write_half_word(addr, val);
		log_store(addr, val);
	}

	void write_byte(const size_t addr, const ubyte val) {
		mem.write_byte(addr, val);
		log_store(addr, val);
	}

	void write_word(const size_t addr, const uint val) {
		mem.write_word(addr, val);
		log_store(addr, val);
	}

	ubyte read_byte(const size_t addr) {
		immutable val = mem.read_byte(addr);
		log_load(addr, val);
		return val;
	}

	ushort read_half_word(const size_t addr) {
		immutable val = mem.read_half_word(addr);
		log_load(addr, val);
		return val;
	}

	uint read_word(const size_t addr) {
		immutable val = mem.read_word(addr);
		log_load(addr, val);
		return val;
	}

	void flip_bit(const uint addr, const uint val) {
		mem.flip_bit(addr, val);
	}

	string get_reg_name(const uint addr) {
		return mem.get_reg_name(addr);
	}

	uint get_ram_origin() {
		return mem.ram_origin;
	}

	uint get_ram_length() {
		return mem.ram_length;
	}

	uint get_flash_origin() {
		return mem.flash_origin;
	}

	uint get_flash_length() {
		return mem.flash_length;
	}
	// --------------------------------------------------------------------------------------

	// ---------------------------------------- Stack ---------------------------------------
	void increment_sp_one_word_width() {
        uint current_sp = cpu.get_sp();
        current_sp += 4;
        cpu.set_sp(current_sp);
    }

    void decrement_sp_one_word_width() {
        uint current_sp = cpu.get_sp();
        current_sp -= 4;
        cpu.set_sp(current_sp);
    }

    void push(const reg r) {
    	push(get_reg(r));
    }

    void push(const uint val) {
        decrement_sp_one_word_width();
        mem.write_word(cpu.get_sp(), val);
        log_push(cpu.get_sp(), val);
    }

    uint pop() {
        immutable res = mem.read_word(cpu.get_sp());
        log_pop(cpu.get_sp(), res);
        increment_sp_one_word_width();
        return res;
    }
    // --------------------------------------------------------------------------------------
	string get_func_name() {
		return "placeholder";
	}

	string get_log_prefix() {
		return format("[TICK:%d][PC:%08X][FUNC:%s]", cpu.get_tick(), cpu.get_pc(), get_func_name());
	}

	void log_pc() {
		auto log_file = pc_log();
		log_file.writeln(get_log_prefix());
		log_file.flush();
	}

	void log_push(const size_t dest_addr, const uint val) {
		auto log_file = stack_log();
		log_file.writeln(get_log_prefix(),format("(%08X pushed to %08X)", val, dest_addr));
		log_file.flush();
	}

	void log_pop(const size_t src_addr, const uint val) {
		auto log_file = stack_log();
		log_file.writeln(get_log_prefix(),format("(%08X popped from %08X)", val, src_addr));
		log_file.flush();
	}

	void log_load(const size_t src_addr, const uint val) {
		auto log_file = load_store_log();
		log_file.writeln(get_log_prefix(), format("(%08X loaded from %08X)", val, src_addr));
		log_file.flush();
	}

	void log_store(const size_t target_addr, const uint val) {
		auto log_file = load_store_log();
		log_file.writeln(get_log_prefix(), format("(%08X stored into %08X)", val, target_addr));
		log_file.flush();
	}
 	// -------------------------------------------------------------------------------------- 
	
	// ====================
	//  Execute Next Instr
	// ====================

	void execute_next_instr() {
		log_pc();
		++cpu.tick;
		if (cpu.tick == 10000) {
			execute_sys_tick(this);
			cpu.tick = 0;
			return;
		}

	    auto inOpt = current_program.find!(ins => ins._addr == cpu.get_pc());
	    if (inOpt is null) {
	        writeln("Error: PC not found in program");
	        return;
	    }

	    auto ins = inOpt.front.i;

	    instr_16 i16;
		bool is16;

		try {
		    i16 = ins.get!instr_16;
		    is16 = true;
		} catch (Exception e) {
		    is16 = false;
		}

		if (is16) {
		    execute_instr(i16, this);
		    return;
		}

		auto i32 = ins.get!instr_32;
		execute_instr(i32, this);
	}

	void run_to(uint addr) {
		while (1) {
			execute_next_instr();
			if (cpu.get_pc() == addr)
				break;
		}
	}
	// -------------------------------------------------------------------------------------- 
}


