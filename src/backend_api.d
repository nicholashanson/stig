import core.memory : GC;
import object : destroy;
import std.string : fromStringz;

import parse_elf;
import cortex_m_core;
import memory_sections;
import vm;
import thumb_2_convert_instr_to_string;
import thumb_2_decode_instr;

interface ivm {
    void step();
    uint get_reg(int r);
    uint get_pc();
    uint[16] get_core_registers();

    void load_word(uint addr, uint value);
    void load_half_word(uint addr, ushort value);
    void set_current_program(addr_instr[] program);
    void init_pc(uint entry_addr);
    void advance_to_next_cycle();
    int get_val_index(uint val);

}

class vm_adapter(T) : ivm {
    T vm;

    this(T vm)
    {
        this.vm = vm;
    }

    void step()
    {
        vm.execute_next_instr();
    }

    uint get_reg(int r)
    {
        return vm.get_reg(cast(reg)r);
    }

    uint get_pc()
    {
        return vm.get_pc();
    }

    void load_word(uint addr, uint value)
	{
	    vm.mem.write_word(addr, value);
	}

	void load_half_word(uint addr, ushort value)
	{
	    vm.mem.write_half_word(addr, value);
	}

	void set_current_program(addr_instr[] program) {
		vm.current_program = program;
	}

	void init_pc(uint entry_addr) {
		vm.init_pc(entry_addr);
	}

    uint[16] get_core_registers() {
        return vm.get_core_registers();
    }

    void advance_to_next_cycle() {
        return vm.advance_to_next_cycle();
    }

    int get_val_index(uint val) {
        return vm.get_val_index(val);
    }
}

class session {
	ivm vm;
    row_view[] rows;

    this(ivm vm)
    {
        this.vm = vm;
    }

    void load_elf(string path) {
        auto e = new elf_file(path);
        auto p = get_program_from_elf(e);
    	rows = generate_instr_rows(p); 
    	foreach (f; p) 
        	load_function_into_memory(f, vm); 
    	addr_instr[] program;
    	foreach (f; p)
        	program ~= f.instrs;
    	vm.set_current_program(program);
    	auto entry_addr = get_elf_entry_point(path);
		vm.init_pc(entry_addr);
    }

    uint get_pc()
    {
        return vm.get_pc();
    }

    uint get_reg(int r)
    {
        return vm.get_reg(r);
    }

    void step()
    {
        vm.step();
    }

    uint[16] get_core_registers() {
        return vm.get_core_registers();
    }

    void vm_advance_to_next_cycle() {
        return vm.advance_to_next_cycle();
    }

    int vm_get_val_index(uint val) {
        return vm.get_val_index(val);
    }
}

session create_session(soc s) {
    switch (s)
    {
version (ARMv7_M) {
        case soc.stm32:
        {
            auto raw = cortex_m_vm!stm32f4_mem();
            return new session(new vm_adapter!(typeof(raw))(raw));
        }
        case soc.nrf:
        {
            auto raw = cortex_m_vm!nrf52840_mem();
            return new session(new vm_adapter!(typeof(raw))(raw));
        }
        case soc.nxp:
        {
            auto raw = cortex_m_vm!rw612_mem();
            return new session(new vm_adapter!(typeof(raw))(raw));
        }
        case soc.s32k16:
        {
            auto raw = cortex_m_vm!s32k146_mem();
            return new session(new vm_adapter!(typeof(raw))(raw));
        }
}
        default:
            assert(0);
    }
}

struct vm_handle {
	session _session;
}

extern(C):

vm_handle* vm_create(int s) {
	soc soc_type = cast(soc)s;
    auto h = new vm_handle;
    h._session = create_session(soc_type);
    return h;
}

extern(C):

void vm_destroy(vm_handle* h) {
    if (!h) return;
    destroy(*h);
    GC.free(h);
}

extern(C):

void vm_load_elf(vm_handle* h, const char* path) {
    if (!h || !path) return;
    string dpath = fromStringz(path).idup;
    h._session.load_elf(dpath);
}

extern(C):

uint vm_get_pc(vm_handle* h) {
	if (!h) return 0;
	return h._session.get_pc();
}

extern(C):

void vm_step(vm_handle* h) {
	if (!h) return;
	return h._session.step();
}

extern(C):

void vm_get_core_registers(vm_handle* h, uint* out_regs) {
    if (!h || !out_regs) return;
    auto regs = h._session.get_core_registers();

    foreach (i; 0 .. 16)
        out_regs[i] = regs[i];
}

extern(C):

void vm_advance_to_next_cycle(vm_handle* h) {
    if (!h) return;
    return h._session.vm_advance_to_next_cycle();
}

extern(C):

enum row_kind {
    func_name,
    blank_line,
    instr
}

struct row_view_c {
    row_kind type;
    const(char)* s;
    size_t s_len;
    uint addr;
}

extern(C):

void vm_get_rows(vm_handle* h, row_view_c** out_, size_t* count) {
    if (!out_ || !count) return;

    auto copy = h._session.rows;

    *count = copy.length;
    *out_ = cast(row_view_c*) GC.malloc(copy.length * row_view_c.sizeof);

    foreach (i; 0 .. copy.length) {
        (*out_)[i].type = cast(typeof((*out_)[i].type)) copy[i].type;
        (*out_)[i].s = copy[i].s.ptr;
        (*out_)[i].s_len = copy[i].s.length;
        (*out_)[i].addr = copy[i].addr;
    }
}

extern(C):

int vm_get_val_index(vm_handle* h, uint val) {
    if (!h) return -1;
    return h._session.vm_get_val_index(val);
}