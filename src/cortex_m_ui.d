import deimos.ncurses;
import cortex_m;
import std.format;
import std.string : toStringz;
import std.variant : VariantN;
import std.stdio;
import std.conv;
import std.algorithm;
import core.runtime : Runtime;
import core.time : MonoTime, dur;
import thumb_2_opcodes;
import thumb_2_instrs;
import memory_sections;
import parse_elf;
import std.array : replicate;
import cortex_m_core;
import load_store_log_;
import std.datetime;

WINDOW*       instr_pad;
WINDOW*         reg_pad;
WINDOW*        flag_pad;
WINDOW*        stackPad;
WINDOW* instr_pad_frame;
int          padPos = 0;

int frame_h;
int frame_w;
int frame_y;
int frame_x;

void init_frames() {
    frame_h =    LINES - 2;
    frame_w =     COLS / 2;
    frame_y =            1;
    frame_x =     COLS / 2;
}

struct reg_cache_item {
    uint    val;
    string    s;
}

reg_cache_item[16] reg_cache;

struct row_view {
    enum kind { func_name, blank_line, instr };
    kind    type;
    string     s;
    uint    addr;
}

row_view[] generate_instr_rows(func[] functions) {
    row_view[] res;
    foreach (f; functions) {
        res ~= row_view(type: row_view.kind.func_name, s: f.name);
        foreach (ins; f.instrs) {
            string s;
            try {
                auto i16 = ins.i.get!instr_16;
                s = convert_to_string(ins._in_16);

                if (i16.op == opcode.b_cond || i16.op == opcode.b_imm_11) {
                    uint target = ins._addr + i16.offset + 4;
                    s ~= format("%8x", target);
                }
                if (i16.op == opcode.cmp_br_z || i16.op == opcode.cmp_br_nz) {
                    uint target = ins._addr + i16.offset + 4;
                    s ~= format(" %4x", target);
                }
                if (i16.op == opcode.ldr_pool) {
                    int base = ins._addr + 4;
                    base &= ~0x3;
                    s ~= format(" @ (%7X)", base + i16.imm);
                }
            }
            catch (Exception e) {
                try {
                    auto i32 = ins.i.get!instr_32;
                    s = convert_to_string(ins._in_32);
                    if (i32.op == opcode.bl_32 || i32.op == opcode.b_32 || i32.op == opcode.b_uncond_32) {
                        uint target = ins._addr + i32.offset + 4;
                        s ~= format(" %x", target);
                    }
                }
                catch (Exception) {
                    s = "Unknown instruction type";
                }
            }

            if (ins._instr_bytes.length == 8) {
                res ~= row_view(type: row_view.kind.instr,
                                addr: ins._addr, 
                                s: format("%x: %s     %s",     ins._addr, ins._instr_bytes, s));
            } else {
                res ~= row_view(type: row_view.kind.instr,
                                addr: ins._addr, 
                                s: format("%x: %s         %s", ins._addr, ins._instr_bytes, s));
            }
        }
        res ~= row_view(type: row_view.kind.blank_line);
    }
    return res;
}

int color_for_value(vm_t)(uint val, ref vm_t vm) {
    if (val == 0x00000000)
        return 1;
    else if (val >= vm.mem.ram_origin   && val <= vm.mem.ram_origin   + vm.mem.ram_length  )
        return 3;
    else if (val >= vm.mem.flash_origin && val <= vm.mem.flash_origin + vm.mem.flash_length)
        return 4;
    else if (val > vm.mem.ram_origin + vm.mem.ram_length)
        return 5;
    return 2;
}

void draw_screen(vm_t)(ref vm_t vm, const ref row_view[] rows) {
    werase(instr_pad);
    static int  start;
    static int    end;
    int reg_x     = 1;
    int reg_y     = 1;
    int flag_y    = 1;
    int flag_x    = 1;

    auto print_reg = (string name, reg r, uint val, ref vm_t vm) {
        string reg_name; 
        if (reg_cache[r].val != val) {
            reg_name = vm.mem.get_reg_name(val);
            if (reg_name == "") {
                foreach (e; vm.objects) {
                if (e.addr == val) {
                        reg_name = e.name;
                        break;
                    }
                }
            }
            const int reg_name_width = COLS / 2 - 18;
            if (reg_name.length < reg_name_width) {
                reg_name ~= replicate(" ", reg_name_width - reg_name.length);
            }
            reg_cache[r].s   = reg_name;
            reg_cache[r].val = val;
        } else {
            reg_name = reg_cache[r].s;
        }
        int color = color_for_value(val, vm);
        wattron(reg_pad, COLOR_PAIR(color));
        mvwprintw(reg_pad, reg_y++, reg_x, toStringz(format("%s %08X %s", name, val, reg_name)));
        wattroff(reg_pad, COLOR_PAIR(color));
    };
    auto print_flag = (string name, bool val) {
        int color  = val ? 4 : 1;
        wattron(flag_pad, COLOR_PAIR(color));
        mvwprintw(flag_pad, flag_y++, reg_x, toStringz(format("%s %d", name, val)));
        wattroff(flag_pad, COLOR_PAIR(color));
    };

    mvwprintw(reg_pad, reg_y++, reg_x, "Core Registers:");
    print_reg("r0: ",              reg.r0, vm.cpu.r0, vm);
    print_reg("r1: ",              reg.r1, vm.cpu.r1, vm);
    print_reg("r2: ",              reg.r2, vm.cpu.r2, vm);
    print_reg("r3: ",              reg.r3, vm.cpu.r3, vm);
    print_reg("r4: ",              reg.r4, vm.cpu.r4, vm);
    print_reg("r5: ",              reg.r5, vm.cpu.r5, vm);
    print_reg("r6: ",              reg.r6, vm.cpu.r6, vm);
    print_reg("r7: ",              reg.r7, vm.cpu.r7, vm);
    print_reg("r8: ",              reg.r8, vm.cpu.r8, vm);
    print_reg("r9: ",              reg.r9, vm.cpu.r9, vm);
    print_reg("r10:",             reg.r10,vm.cpu.r10, vm);
    print_reg("r11:",             reg.r11,vm.cpu.r11, vm);
    print_reg("r12:",             reg.r12,vm.cpu.r12, vm);
    print_reg("sp: ",         reg.sp,vm.cpu.get_sp(), vm);
    print_reg("lr: ",              reg.lr, vm.cpu.lr, vm);
    print_reg("pc: ",              reg.pc, vm.cpu.pc, vm);
    
    mvwprintw(flag_pad, flag_y++, flag_x, "Flags:");
    print_flag("z:",                      vm.cpu.z);
    print_flag("n:",                      vm.cpu.n);
    print_flag("c:",                      vm.cpu.c);
    print_flag("v:",                      vm.cpu.v);
    print_flag("ge0:",                  vm.cpu.ge0);
    print_flag("ge1:",                  vm.cpu.ge1);
    print_flag("ge2:",                  vm.cpu.ge2);
    print_flag("ge3:",                  vm.cpu.ge3);
    print_flag("SPSEL:",             vm.cpu.sp_sel);
    print_flag("NPRIV:",              vm.cpu.npriv);
    print_flag("FAULTMASK:",     vm.cpu.fault_mask);
    print_flag("PRIMASK:",         vm.cpu.pri_mask);
    
    reg_y++;
    flag_y++;

    mvwprintw(flag_pad, flag_y++, reg_x, "IT Stack:");
    string[] it_s = ["first_cond", "x", "y", "z"];
    int i = 0;  
    foreach (item; vm.cpu.it_block_stack) {
        mvwprintw(flag_pad, flag_y++, reg_x, toStringz(format("%s: %s", it_s[i], item.to!string)));
        i++;
    }

    int screen_row     = 0;
    int col            = 1;

    int visible_lines  = 39;
    int current_pc_row = -1;

    int pc_r = 0;
    foreach (r; rows) {
        if (r.addr == vm.cpu.pc) {
            current_pc_row = pc_r;
        }
        pc_r++;
    }

    bool pad_is_focused = (current_pc_row >= start) && (current_pc_row < end);

    if (!pad_is_focused) {
        start = max(0,              current_pc_row - 5);
        end   = min(start + visible_lines, rows.length);
    }

    int bottom_margin =  5;
    int distance_to_bottom = end - current_pc_row;
    if (distance_to_bottom < bottom_margin) {
        int delta = bottom_margin - distance_to_bottom;
        end   = min(end + delta, rows.length);
        start = end - visible_lines;
    }

    for (int j = start; j < end; ++j) {
        auto r = rows[j];
        if (r.type == row_view.kind.func_name) {
            mvwprintw(instr_pad, screen_row++, col, toStringz(r.s));
        }
        if (r.type == row_view.kind.instr) {
            if (r.addr == vm.cpu.pc) {
                wattron(instr_pad, A_REVERSE);
                current_pc_row = j;
            }
            mvwprintw(instr_pad, screen_row++, col, toStringz(r.s));
            if (r.addr == vm.cpu.pc) {
                wattroff(instr_pad, A_REVERSE);
            }
        }
        if (r.type == row_view.kind.blank_line) {
            screen_row++;
        }
    }

    wnoutrefresh(stdscr);

    int regScreenRow =            1;  
    int regScreenCol =            1;   
    int regHeight    =           21;    
    int regWidth     = COLS / 2 - 2;      

    int flagScreenRow = regHeight;   
    int flagScreenCol =         1;   
    int flagHeight    =        26;     
    int flagWidth     =  COLS / 4;

    int stackScreenRow = regHeight;   
    int stackScreenCol =  COLS / 4;   
    int stackHeight    =        26;     
    int stackWidth     =  COLS / 4;

    prefresh(
        reg_pad,
        0,                                                      0,                     
        regScreenRow,                                regScreenCol,   
        regScreenRow + regHeight - 1, regScreenCol + regWidth - 1 
    );
    prefresh(
        flag_pad,
        0,                                                          0,                     
        flagScreenRow,                                  flagScreenCol,   
        flagScreenRow + flagHeight - 1, flagScreenCol + flagWidth - 1 
    );
    prefresh(
        stackPad,
        0, 0,                     
        stackScreenRow,                                    stackScreenCol,   
        stackScreenRow + stackHeight - 1, stackScreenCol + stackWidth - 1 
    );
    wnoutrefresh(instr_pad_frame);
    prefresh(instr_pad,
             0,                                         0,          
             frame_y + 1,                     frame_x + 1,     
             frame_y + frame_h - 2, frame_x + frame_w - 2  
    );
    doupdate();
}

// ==============
//  FIND SYMBOLS
// ==============

void find_symbols(const string elf_filename, const string sym, bool show_size = false) {
    st_name_val[] vals;
    if (show_size) 
        vals = get_st_name_val(elf_filename, st_type.all, soc.all, true, true);
    else 
        vals = get_st_name_val(elf_filename, st_type.all, soc.all, true);
    st_name_val[] matches;
    foreach (v; vals) {
        if (v.name.canFind(sym)) {
            matches ~= v;
        }
    }
    if (matches.length == 0) {
        writeln(format("No matching symbols found in %s", elf_filename));
        return;
    }

    foreach (m; matches) {
        string s;
        if (show_size) 
            s = format("%s: %X, size: %d", m.name, m.addr, m.size);
        else 
            s = format("%s: %X", m.name, m.addr);
        writeln(s);
    }
    writeln(format("%d matching symbols found", matches.length));
}

// ==================
//  GET SECTION SIZE
// ==================

void get_section_size(const string elf_filename, const string section_name) {
    auto section = get_section_by_name(elf_filename, section_name);
    writeln(format("%s size: %d", section.name, section.data.length));
}

struct runtime_ctrl {
    bool     is_playing = false;
    MonoTime last_time;
    Duration interval;       
    MonoTime last_draw;
    Duration frame_interval; 
}

void stm32_control_loop(ref runtime_ctrl ctrl, ref cortex_m_vm!stm32f4_mem vm, ref row_view[] rows) {
    int ch;
    while (true) {
        ch = getch();

        if (ch != ERR) {
            if (ch == 'q') {
                break;
            }
            if (ch == KEY_DOWN) {
                vm.execute_next_instr();
            }
            if (ch == ' ') { 
                ctrl.is_playing = !ctrl.is_playing;
            }               
            if (ch == 'p') {
                vm.mem.flip_bit(0x40023800, 25);
            }  
            if (ch == 'y') {
                vm.mem.flip_bit(0x40023800, 27);
            }  
        }

        auto now = MonoTime.currTime;
        if (ctrl.is_playing) {
            auto delta = now - ctrl.last_time; 
            if (delta >= ctrl.interval) {
                vm.execute_next_instr();
                ctrl.last_time = now;
            }
        }
        draw_screen(vm, rows);
    }
}

void nrf_control_loop(ref runtime_ctrl ctrl, ref cortex_m_vm!nrf52840_mem vm, ref row_view[] rows) {
    int ch;
    while (true) {
        ch = getch();

        if (ch != ERR) {
            if (ch == 'q') {
                break;
            }
            if (ch == KEY_DOWN) {
                vm.execute_next_instr();
            }
            if (ch == ' ') { 
                ctrl.is_playing = !ctrl.is_playing;
            }             
        }

        auto now = MonoTime.currTime;
        if (ctrl.is_playing) {
            auto delta = now - ctrl.last_time; 
            if (delta >= ctrl.interval) {
                vm.execute_next_instr();
                ctrl.last_time = now;
            }
        }
        draw_screen(vm, rows);
    }
}

void load_elf(vm_t)(ref vm_t vm, soc mcu, const string target_file_name) {
    auto f_h = load_store_log();
    f_h.writeln("Loading program");
    f_h.flush();
    auto f_s = get_program_from_elf(target_file_name);
    vm.cpu.pc = get_elf_entry_point(target_file_name) - 1;
    if (f_s.length == 0) {
        f_h.writeln("No functions found");
        f_h.flush();
    }
    foreach (f; f_s) {
        load_function_into_memory(f, vm.mem);
        f_h.writeln(f.name, ": ", f.instrs.length);
        f_h.flush();
        vm.current_program ~= f.instrs;
        vm.func_names ~= f.name;
        f_h.writeln(vm.current_program.length);
        f_h.flush();
    }
    foreach (t; table_names) {
        load_section_into_memory(target_file_name, t, vm.mem);
    }
    vm.objects  = get_st_name_val(target_file_name, st_type.stt_func,   mcu);
    vm.objects ~= get_st_name_val(target_file_name, st_type.stt_notype, mcu);
    vm.objects ~= get_st_name_val(target_file_name, st_type.stt_object, mcu);
}

void main(string[] args) {
    auto ctrl = runtime_ctrl();
    ctrl.last_time      = MonoTime.currTime;
    ctrl.interval       =   dur!"msecs"(20);
    ctrl.last_draw      = MonoTime.currTime;
    ctrl.frame_interval =   dur!"msecs"(33);

    uint   entry_point = 0; 
    string first_arg;
    string target_file_name;
    string soc_s;

    if (args.length > 1) {
        first_arg = args[1];
    }

    switch (first_arg) {
        case "syms"        : find_symbols(args[2], args[3]);       return;
        case "syms_size"   : find_symbols(args[2], args[3], true); return;
        case "section_size": get_section_size(args[2], args[3]);   return;
        default            :                                        break;
    }

    target_file_name = first_arg;

    if (args.length > 2) {
        soc_s = args[2];
    }

    if (soc_s != "nrf" && soc_s != "stm32") {
        writeln("Unrecognized SoC: ", soc_s);
        return;
    }

    if (args.length > 3) {
        try {
            entry_point = to!uint(args[3], 16);
        } catch (ConvException e) {
            writeln("Invalid entry point: ", args[3]);
            return;
        }
    }

    initscr();
    init_frames();
    curs_set(0);
    start_color();
    use_default_colors();

    start_color();
    init_color(COLOR_WHITE,  970, 970, 950);
    init_color(COLOR_CYAN,   400, 850, 940);
    init_color(COLOR_YELLOW, 900, 860, 450);
    init_color(COLOR_GREEN,  650, 880, 180);
    init_color(COLOR_RED,    980, 150, 450);
    init_color(8,            500, 500, 500);
    init_color(9,            248, 248, 248);

    init_pair(1, COLOR_WHITE,  COLOR_BLACK); 
    init_pair(2, COLOR_CYAN,   COLOR_BLACK); 
    init_pair(3, COLOR_YELLOW, COLOR_BLACK); 
    init_pair(4, COLOR_GREEN,  COLOR_BLACK); 
    init_pair(5, COLOR_RED,    COLOR_BLACK);
    init_pair(6, COLOR_WHITE,            8);
    init_pair(7, COLOR_WHITE,            9); 
    
    scope(exit) endwin();
    cbreak();
    noecho();
    keypad(stdscr, true);

    timeout(20);

    instr_pad_frame = newwin(frame_h, frame_w, frame_y, frame_x);

    reg_pad   = newpad(19, COLS / 2 - 2);
    flag_pad  = newpad(15, COLS / 4 - 2);
    stackPad  = newpad(20,     COLS / 4);
    instr_pad = newpad(10000,       200);

    box(reg_pad,         0, 0);
    box(flag_pad,        0, 0);
    box(instr_pad_frame, 0, 0);

    func[] f_s;
    f_s = get_program_from_elf(target_file_name);
    auto rows = generate_instr_rows(f_s);

    if (soc_s == "nrf") {
        cortex_m_vm!nrf52840_mem vm;
        load_elf(vm, soc.nrf, target_file_name);
        if (entry_point != 0) {
            vm.run_to(entry_point);
        }
        draw_screen(vm, rows);
        nrf_control_loop(ctrl, vm, rows);
    } else {
        cortex_m_vm!stm32f4_mem vm;
        load_elf(vm, soc.stm32, target_file_name);
        if (entry_point != 0) {
            vm.run_to(entry_point);
        }
        draw_screen(vm, rows);
        stm32_control_loop(ctrl, vm, rows);
    }

    endwin();
}

