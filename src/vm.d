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
    void write_word(const size_t addr, uint val) {}
    uint read_word(const size_t addr) { return 0; }
    void write_byte(const size_t addr, ubyte val) {}
    ubyte read_byte(const size_t addr) { return 0; }
    void write_half_word(const size_t addr, ushort val) {}
    ushort read_half_word(const size_t addr) { return 0; }
    void flip_bit(const uint addr, const uint bit) {}
    string get_reg_name(const uint addr) { return ""; }
    void set_vtor() {}
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
	st_name_val[] func_map;
	string latest_load_store;

	bool opEquals(const ref typeof(this) rhs) const {
        return cpu == rhs.cpu
            && mem == rhs.mem;
    }

    // ============================
	//  Current Mode is Privileged
	// ============================

    // boolean CurrentModeIsPrivileged()
	// return (CurrentMode == Mode_Handler || CONTROL.nPRIV == ‘0’);
    bool current_mode_is_privileged() {
    	return (get_current_exception() != exception.thread_mode) | !get_npriv();
    }
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

	uint get_ipsr() {
		return cpu.get_ipsr();
	}

	uint get_apsr() {
		return cpu.get_apsr();
	}

	void set_apsr(const uint v) {
		cpu.set_apsr(v);
	}

	void set_fpca(const bool v) {
		cpu.fpca = v;
	}

	bool get_sp_sel() const {
		return cpu.sp_sel;
	}

	void set_sp_sel(bool v) {
		cpu.sp_sel = v;
	}

	void set_fault_mask(bool v) {
		cpu.fault_mask = v;
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

	bool get_fpca() {
		return cpu.fpca;
	}

	void set_ipsr(const uint ipsr) {
		cpu.set_ipsr(ipsr);
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
	bool pendsv_is_pending() {
		auto val = mem.read_word(0xE000ED04);
		return cast(bool)slice(val, 28, 1);
	}

	void set_vtor() {
		mem.set_vtor();
	}

	void load_half_word(const size_t addr, const ushort val) {
		mem.write_half_word(addr, val);
	}

	void load_byte(const size_t addr, const ubyte val) {
		mem.write_byte(addr, val);
	}

	void load_word(const size_t addr, const uint val) {
		mem.write_word(addr, val);
	}

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
		return mem.get_reg_name(addr & ~0x3);
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
	string get_func_name(const uint val) {
		foreach (f; func_map) {
        	if (val >= (f.addr & ~1) && val - (f.addr & ~1) < f.size) {
            	return f.name;
        	}
    	}
    	return "UNKNOWN";;
	}

	string get_log_prefix() {
		return format("[%d][%X][%s]", cpu.get_tick(), 
									  cpu.get_pc(), 
									  get_func_name(cpu.get_pc()));
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

	string get_latest_load_store() const {
		return latest_load_store;
	}

	string 
	get_format
	(T)
	(const T val) {
		static if (is(T == ubyte))
			return "%02X";
		else static if (is(T == ushort))
        	return "%04X";
    	else
    		return "%08X";
    }

    // =========
	//  Log MSR
	// =========

	void 
	log_msr
	(T)
	(const string spec_reg, const T val) {
		auto log_file = load_store_log();
		string s = get_format(val);
		string msr_msg = get_log_prefix() ~ format("(0x" ~ s ~ " stored into %s)", 
												    val, spec_reg);
		latest_load_store = msr_msg;
		log_file.writeln(msr_msg);
		log_file.flush();
	} 

	// =========
	//  Log MRS
	// =========

	void 
	log_mrs
	(T)
	(const string spec_reg, const T val) {
		auto log_file = load_store_log();
		string s = get_format(val);
		string mrs_msg = get_log_prefix() ~ format("(0x" ~ s ~ " loaded from %s)", 
												    val, spec_reg);
		latest_load_store = mrs_msg;
		log_file.writeln(mrs_msg);
		log_file.flush();
	}

	// ==========
	//  Log Load
	// ==========

	void 
	log_load
	(T)
	(const size_t src_addr, const T val) {
		auto log_file = load_store_log();
		auto reg_name = mem.get_reg_name(cast(uint)src_addr);
		string s = get_format(val);
    	string load_msg = get_log_prefix() ~ format("(0x" ~ s ~ " loaded from 0x%08X%s)", 
												    val, src_addr, 
												    reg_name != "" ? "[" ~ reg_name ~ "]" : "");
		latest_load_store = load_msg;
		log_file.writeln(load_msg);
		log_file.flush();
	}

	// ===========
	//  Log Store
	// ===========

	void 
	log_store
	(T)
	(const size_t target_addr, const T val) {
		auto log_file = load_store_log();
		auto reg_name = mem.get_reg_name(cast(uint)target_addr);
		string s;
		static if (is(T == ubyte))
			s = "%02X";
		else static if (is(T == ushort))
        	s = "%04X";
    	else
    		s = "%08X";
    	string store_msg = get_log_prefix() ~ format("(0x" ~ s ~ " stored into 0x%08X%s)", 
												     val, target_addr, 
												     reg_name != "" ? "[" ~ reg_name ~ "]" : "");
    	latest_load_store = store_msg;
		log_file.writeln(store_msg);
		log_file.flush();
	}
 	// -------------------------------------------------------------------------------------- 
	
	// ====================
	//  Execute Next Instr
	// ====================

	void execute_next_instr() {
		log_pc();
		++cpu.tick;
		if (pendsv_is_pending()) {
			enter_exec(exception.pendsv_irqn, this);
			return;
		}
		if (cpu.tick == 10000) {
			enter_exec(exception.systick_irqn, this);
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


