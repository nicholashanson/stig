import std.format;
import std.algorithm;
import std.stdio;
import std.range;
import std.traits : isIntegral;

import log;
import scb_defs;
import parse_elf;
import cortex_m_core;
import cortex_m_scb;
import memory_sections;
import thumb_2_instrs;
import thumb_2_decode_instr;
import thumb_2_execute_instr;

// ===========
//  DUMMY MEM
// ===========

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
    uint peek_word(size_t addr) {
        uint res;
        return res;
    }
}
// --------------------------------------------------------------------------------------

alias test_vm = cortex_m_vm!(dummy_mem);
alias tiny_vm = cortex_m_vm!(tiny_mem);
alias stm32f4_vm = cortex_m_vm!(stm32f4_mem);
// --------------------------------------------------------------------------------------

// ==============
//  CPU PROPERTY
// ==============

mixin template cpu_property(string name) {
    mixin(
        "auto get_" ~ name ~ "() const {\n" ~
        "    return cpu.get_" ~ name ~ "();\n" ~
        "}\n" ~
        "\n" ~
        "void set_" ~ name ~
        "(typeof(cpu.get_" ~ name ~ "()) v) {\n" ~
        "    cpu.set_" ~ name ~ "(v);\n" ~
        "}\n"
    );
}

// ***************************************************************************************
// *					              CORTEX M VM 										 *
// ***************************************************************************************

struct cortex_m_vm(mem_t) {
	cortex_m_cpu cpu;
	mem_t mem;
	addr_instr[]  current_program;
	string[] 	  func_names;
	st_name_val[] objects;
	st_name_val[] func_map;
	string 		  latest_load_store;
	// --------------------------------------------------------------------------------------

	bool opEquals(const ref typeof(this) rhs) const {
        return cpu == rhs.cpu
            && mem == rhs.mem;
    }
    // --------------------------------------------------------------------------------------
    // ============================
	//  CURRENT MODE IS PRIVILEGED
	// ============================

    // boolean CurrentModeIsPrivileged()
	// return (CurrentMode == Mode_Handler || CONTROL.nPRIV == ‘0’);
    bool current_mode_is_privileged() {
    	return (get_curr_exc() != exception.thread_mode) | !get_npriv();
    }
	// ----------------------------------------- PC ----------------------------------------- 
	private bool pc_modified;

	// ========
	//  GET PC
	// ========

	uint get_pc() const {
		return cpu.get_pc();
	}

	// ===================
	//  CHECK PC MODIFIED
	// ===================

	bool check_pc_modified() {
		bool res = pc_modified;
		pc_modified = false;
		return res;
	}

	// ==============
	//  INCREMENT PC
	// ==============

	void increment_pc(const uint val) {
		cpu.increment_pc(val);
	}

	// =================
	//  CLEAR THUMB BIT
	// =================

	void clear_thumb_bit() {
		cpu.clear_thumb_bit();
	}

	// =========
	//  INIT PC
	// =========

	void init_pc(const uint v) {
		cpu.set_reg(reg.pc, v);
	}

	// ==========
	//  ALIGN PC
	// ==========

	void align_pc() {
		cpu.align_pc();
	}
	// --------------------------------------------------------------------------------------
	// ================
	//  CPU PROPERTIES
	// ================

	mixin cpu_property!"curr_exc";
	mixin cpu_property!"xpsr";
	mixin cpu_property!"apsr";
	mixin cpu_property!"sp_sel";
	mixin cpu_property!"ge0";
	mixin cpu_property!"ge1";
	mixin cpu_property!"ge2";
	mixin cpu_property!"ge3";
	mixin cpu_property!"fpca";
	mixin cpu_property!"basepri";
	mixin cpu_property!"npriv";
	mixin cpu_property!"ipsr";
	mixin cpu_property!"psp";
	mixin cpu_property!"msp";
	// --------------------------------------------------------------------------------------
	// ========
	//  GET SP
	// ========

	uint get_sp() {
		return cpu.get_sp();
	}
	// ---------------------------------------- Flags ---------------------------------------
	// =======
	//  GET C
	// =======
	bool get_c() {
		return cpu.get_c();
	}

	// =======
	//  SET C
	// =======
	void set_c(t)(const t v) {
		cpu.set_c(v);
	}
	// --------------------------------------------------------------------------------------
	// =======
	//  GET V
	// =======
	bool get_v() {
		return cpu.get_v();
	}

	// =======
	//  SET V
	// =======
	void set_v(t)(const t v) {
		cpu.set_v(v);
	}
	// --------------------------------------------------------------------------------------
	// =======
	//  GET N
	// =======
	bool get_n() {
		return cpu.get_n();
	}

	// =======
	//  SET N
	// =======
	void set_n(t)(const t v) {
		cpu.set_n(v);
	}
	// --------------------------------------------------------------------------------------
	// =======
	//  GET Z
	// =======
	bool get_z() {
		return cpu.get_z();
	}

	// =======
	//  SET N
	// =======
	void set_z(t)(t v) if (isIntegral!t) {
    	cpu.set_z(v);
	}
	// --------------------------------------------------------------------------------------
	// =======
	//  SET Q
	// =======

	void set_q(const bool v) {
		cpu.q = v;
	}

	// ==============
	//  GET PRI MASK
	// ==============

	bool get_pri_mask() {
		return cpu.pri_mask;
	}

	// ================
	//  GET FAULT MASK
	// ================

	uint get_fault_mask() const {
		return cpu.get_fault_mask();
	}

	// ================
	//  SET FAULT MASK
	// ================

	void set_fault_mask(const bool v) {
		return cpu.set_fault_mask(v);
	}

	// ===========
	//  SET FPSCR
	// ===========

	void set_fpscr(const uint v) {
		cpu.set_fpscr(v);
	}
	// -------------------------------------- IT BLOCK -------------------------------------- 
	// =============
	//  IN IT BLOCK
	// =============

	bool in_it_block() {
		return cpu.in_it_block();
	}

	// ==============
	//  SET IT BLOCK
	// ==============

	void set_it_block(const xyz it_block) {
		cpu.it_block = it_block;
	}

	// =====================
	//  INIT IT BLOCK STACK
	// =====================

	void init_it_block_stack(const condition cond) {
		cpu.init_it_block_stack(cond);
	}

	// ====================
	//  GET IT BLOCK STACK
	// ====================

	auto get_it_block_stack() {
		return cpu.it_block_stack;
	}

	// ======================
	//  IT BLOCK STACK EMPTY
	// ======================

	bool it_block_stack_empty() {
		return cpu.it_block_stack.empty;
	}

	// =====================
	//  IT CONDITION IS MET
	// =====================

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
	// --------------------------------------------------------------------------------------
	// =========
	//  GET REG
	// =========	

	uint[16] get_core_registers() const {
		return cpu.get_core_registers();
	}

	// =========
	//  GET REG
	// =========	

	uint get_reg(const reg r) const {
		return cpu.get_reg(r);
	}

	// =========
	//  SET REG
	// =========

	void set_reg(const reg r, const uint val) {
		if (r == reg.pc) 
			pc_modified = true;
		cpu.set_reg(r, val);
	} 
	// ---------------------------------------- Memory --------------------------------------
	// ===================
	//  PENDSV IS PENDING
	// ===================

	bool pendsv_is_pending() {
		auto val = mem.read_word(ICSR);
		return cast(bool)slice(val, 28, 1);
	}

	// ==========
	//  SET VTOR
	// ==========

	void set_vtor() {
		mem.set_vtor();
	}

	// =====================
	//  SYS TICK IS ENABLED
	// =====================

	bool sys_tick_is_enabled() {
		uint v = mem.peek_word(SYST_CSR);
		return cast(bool)(v & 0x1);
	}

	// ====================
	//  DECREMENT SYS TICK
	// ====================

	void decrement_sys_tick() {
		uint v = mem.peek_word(SYST_CVR);		
		if (v == 0) {
        	uint reload = mem.peek_word(SYST_RVR) & 0x00FFFFFF;
        	mem.write_word(SYST_CVR, reload);
		} else {
			v -= 1;
			mem.write_word(SYST_CVR, v);
			if (v == 0) {
				uint c = mem.peek_word(SYST_CSR);
				c |= 0x00010000;
				mem.write_word(SYST_CSR, c);
			}
		}
	}

	// =================
	//  SYS TICK IS DUE
	// =================

	bool sys_tick_is_due() {
		return (mem.read_word(SYST_CSR) & 0x00010000) != 0;
	}

	// =================
	//  HANDLE SYS TICK
	// =================

	void handle_sys_tick() {
		uint reload_val = mem.read_word(SYST_RVR);
		mem.write_word(SYST_CVR, reload_val & 0x00FFFFFF);
	}
	// --------------------------------------------------------------------------------------
	// ===========
	//  LOAD BYTE
	// ===========
	void load_byte(const size_t addr, const ubyte val) {
		mem.write_byte(addr, val);
	}

	// ================
	//  LOAD HALF WORD
	// ================	
	void load_half_word(const size_t addr, const ushort val) {
		mem.write_half_word(addr, val);
	}

	// ===========
	//  LOAD WORD
	// ===========	
	void load_word(const size_t addr, const uint val) {
		mem.write_word(addr, val);
	}
	// --------------------------------------------------------------------------------------
	// ===========
	//  READ BYTE
	// ===========	
	ubyte read_byte(const size_t addr) {
		immutable val = mem.read_byte(addr);
		log_load(addr, val);
		return val;
	}

	// ============
	//  WRITE BYTE
	// ============	
	void write_byte(const size_t addr, const ubyte val) {
		mem.write_byte(addr, val);
		log_store(addr, val);
	}
	// --------------------------------------------------------------------------------------
	// ================
	//  READ HALF WORD
	// ================	
	ushort read_half_word(const size_t addr) {
		immutable val = mem.read_half_word(addr);
		log_load(addr, val);
		return val;
	}

	// =================
	//  WRITE HALF WORD
	// =================	
	void write_half_word(const size_t addr, const ushort val) {
		mem.write_half_word(addr, val);
		log_store(addr, val);
	}
	// --------------------------------------------------------------------------------------
	// ===========
	//  READ WORD
	// ===========	
	uint read_word(const size_t addr) {
		immutable val = mem.read_word(addr);
		log_load(addr, val);
		return val;
	}

	// ===========
	//  PEEK WORD
	// ===========	
	uint peek_word(const size_t addr) {
		return mem.read_word(addr);
	}

	// ============
	//  WRITE WORD
	// ============	
	void write_word(const size_t addr, const uint val) {
		mem.write_word(addr, val);
		log_store(addr, val);
	}
	// --------------------------------------------------------------------------------------
	// ==========
	//  FLIP BIT
	// ==========	

	void flip_bit(const uint addr, const uint val) {
		mem.flip_bit(addr, val);
	}
	// --------------------------------------------------------------------------------------
	// ==============
	//  GET REG NAME
	// ==============

	string get_reg_name(const uint addr) {
		return mem.get_reg_name(addr & ~0x3);
	}
	// --------------------------------------------------------------------------------------
	// ================
	//  GET RAM ORIGIN
	// ================

	uint get_ram_origin() {
		return mem.ram_origin;
	}

	// ================
	//  GET RAM LENGTH
	// ================

	uint get_ram_length() {
		return mem.ram_length;
	}
	// --------------------------------------------------------------------------------------
	// ==================
	//  GET FLASH ORIGIN
	// ==================

	uint get_flash_origin() {
		return mem.flash_origin;
	}

	// ==================
	//  GET FLASH LENGTH
	// ==================

	uint get_flash_length() {
		return mem.flash_length;
	}
	// ---------------------------------------- Stack ---------------------------------------
	// =============================
	//  INCREMENT SP ONE WORD WIDTH
	// =============================

	void increment_sp_one_word_width() {
        uint current_sp = cpu.get_sp();
        current_sp += 4;
        cpu.set_sp(current_sp);
    }

    // =============================
	//  DECREMENT SP ONE WORD WIDTH
	// =============================

    void decrement_sp_one_word_width() {
        uint current_sp = cpu.get_sp();
        current_sp -= 4;
        cpu.set_sp(current_sp);
    }
    // -------------------------------------------------------------------------------------- 
    // ======
	//  PUSH
	// ======

	void push(const reg r) {
    	push(get_reg(r));
    }

    void push(const uint val) {
        decrement_sp_one_word_width();
        mem.write_word(cpu.get_sp(), val);
        log_push(cpu.get_sp(), val);
    }
    // -------------------------------------------------------------------------------------- 
    // =====
	//  POP
	// =====

    uint pop() {
        immutable res = mem.read_word(cpu.get_sp());
        log_pop(cpu.get_sp(), res);
        increment_sp_one_word_width();
        return res;
    }
	// -------------------------------------------------------------------------------------- 
    // ===============
	//  GET FUNC NAME
	// ===============

	string get_func_name(const uint val) {
		foreach (f; func_map) {
        	if (val >= (f.addr & ~1) && val - (f.addr & ~1) < f.size) {
            	return f.name;
        	}
    	}
    	return "UNKNOWN";;
	}
	// -------------------------------------------------------------------------------------- 
    // ================
	//  GET LOG PREFIX
	// ================

	string get_log_prefix() {
		return format("[%d][%X][%s]", cpu.get_tick(), 
									  cpu.get_pc(), 
									  get_func_name(cpu.get_pc()));
	}
	// -------------------------------------------------------------------------------------- 
    // ========
	//  LOG PC
	// ========

	void log_pc() {
		auto log_file = pc_log();
		log_file.writeln(get_log_prefix());
		log_file.flush();
	}
	// -------------------------------------------------------------------------------------- 
    // ==========
	//  LOG PUSH
	// ==========

	void log_push(const size_t dest_addr, const uint val) {
		auto log_file = stack_log();
		log_file.writeln(get_log_prefix(),format("(%08X pushed to %08X)", val, dest_addr));
		log_file.flush();
	}
	// -------------------------------------------------------------------------------------- 
    // =========
	//  LOG POP
	// =========

	void log_pop(const size_t src_addr, const uint val) {
		auto log_file = stack_log();
		log_file.writeln(get_log_prefix(),format("(%08X popped from %08X)", val, src_addr));
		log_file.flush();
	}
	// -------------------------------------------------------------------------------------- 
    // =======================
	//  GET LATEST LOAD STORE
	// =======================

	string get_latest_load_store() const {
		return latest_load_store;
	}
	// -------------------------------------------------------------------------------------- 
    // ============
	//  GET FORMAT
	// ============

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
    // -------------------------------------------------------------------------------------- 
    // =========
	//  LOG MSR
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
	// -------------------------------------------------------------------------------------- 
	// =========
	//  LOG MRS
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
	// -------------------------------------------------------------------------------------- 
	// ==========
	//  LOG LOAD
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
	// -------------------------------------------------------------------------------------- 
	// ===========
	//  LOG STORE
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
	// =========
	//  PEND ST
	// =========

	void pend_st() {
		write_word(ICSR,  (1u << PENDSTSET));
	}
	// -------------------------------------------------------------------------------------- 
	// =========
	//  PEND SV 
	// =========

	void pend_sv() {
        write_word(ICSR,  (1u << PENDSVSET));
	}	
	// -------------------------------------------------------------------------------------- 

 	// -------------------------------------------------------------------------------------- 
	// ====================
	//  EXECUTE NEXT INSTR
	// ====================

	void execute_next_instr() {
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
	// -------------------------------------------------------------------------------------- 

	// -------------------------------------------------------------------------------------- 
	// =================
	//  CHECK EXCEPTION
	// =================

	bool check_exception() {
		immutable exc = get_next_executable_exception(this);
		if (exc != exception.thread_mode) {
			enter_exec(exc, this);
			return true;
		}
		if (sys_tick_is_enabled()) {
			decrement_sys_tick();	
			if (sys_tick_is_due()) {
				handle_sys_tick();	
				pend_st();
				return true;
			}			
		}
		return false;
	}
	// -------------------------------------------------------------------------------------- 

	// -------------------------------------------------------------------------------------- 
	// =======================
	//  ADVANCE TO NEXT CYCLE
	// =======================

	void advance_to_next_cycle() {
		log_pc();
		++cpu.tick;
		if (cpu.tick == 10000)
			cpu.tick = 0;
		if (check_exception()) 
			return;
		execute_next_instr();
	}
	// -------------------------------------------------------------------------------------- 

	// -------------------------------------------------------------------------------------- 
	// ================
	//  SECURITY STATE
	// ================

	enum security_state {
		non_secure,
		secure
	}

	security_state curr_state;
	// -------------------------------------------------------------------------------------- 
	// ========
	//  RUN TO
	// ========

	void run_to(const uint addr, const uint nth_instance = 0) {
		uint it = 0;
		while (1) {
			execute_next_instr();
			if (cpu.get_pc() == addr) {
				if (it == nth_instance)
					break;
				else
					it++;
			}
		}
	}
	// -------------------------------------------------------------------------------------- 
}

// --------------------------------------------------------------------------------------
unittest {
	stm32f4_vm vm;
	vm.write_word(ICSR,  (1u << PENDSTSET));
	vm.write_word(SHPR3, 0x10000000);
	immutable highest_exc = get_next_executable_exception(vm);
	assert(highest_exc == exception.systick_irqn);

	vm.set_basepri(0x10);
	assert(get_next_executable_exception(vm) == exception.thread_mode);

	vm.set_basepri(0x0);
	assert(get_next_executable_exception(vm) == exception.systick_irqn);

	vm.write_word(SHPR3, 0x10F00000);
	assert(get_next_executable_exception(vm) == exception.systick_irqn);

	vm.write_word(ICSR,  (1u << PENDSTCLR) | (1u << PENDSVSET));
	assert(get_next_executable_exception(vm) == exception.pendsv_irqn);	

	vm.set_basepri(0xD0);
	assert(get_next_executable_exception(vm) == exception.thread_mode);
}
// --------------------------------------------------------------------------------------

