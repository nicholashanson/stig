import deimos.ncurses;
import std.container;
import std.format;
import std.string   : toStringz;
import std.variant  : VariantN;
import std.stdio;
import std.conv;
import std.algorithm;
import core.runtime : Runtime;
import core.time    : MonoTime, dur;
import std.array;
import std.datetime;
import std.regex;

import vm;
import cortex_m_core;
import memory_sections;
import parse_elf;
import thumb_2_instrs;
import thumb_2_decode_instr;
import thumb_2_execute_instr;
import thumb_2_convert_instr_to_string;
import scb_defs;

WINDOW*       instr_pad;
WINDOW*         reg_pad;
WINDOW*        flag_pad;
WINDOW* instr_pad_frame;
WINDOW*  load_store_pad;
WINDOW*         scb_pad;
bool    pc_moved = true;
int               start;
int                 end;
int visible_lines  = 39;

int view_n        =     0;
bool view_changed = false;

string[] load_store_buffer;
st_name_val[] z_vars;
st_name_val[] z_configs;

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

int color_for_value
(vm_t)
(const uint val, ref vm_t vm) {
    if (val == 0x00000000)
        return 1;
    else if (val >= vm.get_ram_origin()   && val <= vm.get_ram_origin()   + vm.get_ram_length()  )
        return 3;
    else if (val >= vm.get_flash_origin() && val <= vm.get_flash_origin() + vm.get_flash_length())
        return 4;
    else if (val >  vm.get_ram_origin() + vm.get_ram_length())
        return 5;
    return 2;
}

void print_colored_line(WINDOW* win, int row, int col, string line) {
    auto tokens = split_instr(line);
    int x = col;
    foreach (t; tokens) {
        if (regs.canFind(t)) {
            wattron(win, COLOR_PAIR(3)); 
            mvwprintw(win, row, x, toStringz(t));
            wattroff(win, COLOR_PAIR(3));
        } else {
            mvwprintw(win, row, x, toStringz(t));
        }
        x += t.length; 
    }
}

void append_unique(ref string[] buffer, string next, size_t n) {
    if (next == "") 
        return;

    size_t max_len = COLS / 2 - 5;
    if (next.length > max_len)
        next = next[0 .. max_len - 3] ~ "...";

    if (buffer.empty || buffer.back != next)
        buffer ~= next;
    while (buffer.length > n)
        buffer = buffer[1 .. $];
}

void draw_screen_0(vm_t)(ref vm_t vm, const ref row_view[] rows) {
    visible_lines = LINES;
    werase(instr_pad);
    werase(load_store_pad);
    box(instr_pad_frame, 0, 0);
    box(load_store_pad,  0, 0);

    int reg_screen_row   =            1;  
    int reg_screen_col   =            1;   
    int reg_height       =           21;    
    int reg_width        = COLS / 2 - 2;      

    int flag_screen_row = reg_height -1;   
    int flag_screen_col =             1;   
    int flag_height     =             8;     
    int flag_width      =  COLS / 2 - 2;

    int load_store_screen_row = reg_height + 5;   
    int load_store_screen_col =              1;   
    int load_store_height     =     LINES - 25;  
    int load_store_width      =   COLS / 2 - 2;

    int reg_x        = 1;
    int reg_y        = 1;
    int flag_y       = 1;
    int flag_x       = 1;
    int load_store_x = 1;
    int load_store_y = 1;

    auto print_reg = (string name, reg r, ref vm_t vm) {
        uint val; 
        if (r == reg.pc) 
            val = vm.get_pc();
        else
            val = vm.get_reg(r);
        string reg_name; 
        if (reg_cache[r].val != val) {
            reg_name = vm.get_reg_name(val);
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

    bool first_flag = true;
    auto print_flag = (string name, bool val, const int flag_x_) {
        int color  = val ? 4 : 1;
        if (!first_flag && (flag_x_ == 1)) {
            ++flag_y;
        } else {
            first_flag = false;
        }
        wattron(flag_pad, COLOR_PAIR(color));
        mvwprintw(flag_pad, flag_y, flag_x_, toStringz(format("%s %d", name, val)));
        wattroff(flag_pad, COLOR_PAIR(color));
    };

    // ================
    //  CORE REGISTERS
    // ================

    mvwprintw(reg_pad, reg_y++, reg_x, "Core Registers:");
    print_reg("r0: ",                         reg.r0, vm);
    print_reg("r1: ",                         reg.r1, vm);
    print_reg("r2: ",                         reg.r2, vm);
    print_reg("r3: ",                         reg.r3, vm);
    print_reg("r4: ",                         reg.r4, vm);
    print_reg("r5: ",                         reg.r5, vm);
    print_reg("r6: ",                         reg.r6, vm);
    print_reg("r7: ",                         reg.r7, vm);
    print_reg("r8: ",                         reg.r8, vm);
    print_reg("r9: ",                         reg.r9, vm);
    print_reg("r10:",                        reg.r10, vm);
    print_reg("r11:",                        reg.r11, vm);
    print_reg("r12:",                        reg.r12, vm);
    print_reg("sp: ",                         reg.sp, vm);
    print_reg("lr: ",                         reg.lr, vm);
    print_reg("pc: ",                         reg.pc, vm);

    // ==============
    //  FLAG COLUMNS
    // ==============

    int flag_col_1 =                    1;
    int flag_col_2 =  flag_width      / 4;
    int flag_col_3 =  flag_width      / 2;
    int flag_col_4 = (flag_width / 4) * 3; 

    // =======
    //  FLAGS
    // =======
        
    mvwprintw(flag_pad,     flag_y++,        flag_x,          "Flags:");
    print_flag("z:",                            vm.get_z(), flag_col_1);
    print_flag("n:",                            vm.get_n(), flag_col_2);
    print_flag("c:",                            vm.get_c(), flag_col_3);
    print_flag("v:",                            vm.get_v(), flag_col_4);
    print_flag("ge0:",                        vm.get_ge0(), flag_col_1);
    print_flag("ge1:",                        vm.get_ge1(), flag_col_2);
    print_flag("ge2:",                        vm.get_ge2(), flag_col_3);
    print_flag("ge3:",                        vm.get_ge3(), flag_col_4);
    print_flag("SPSEL:",                   vm.get_sp_sel(), flag_col_1);
    print_flag("NPRIV:",                    vm.get_npriv(), flag_col_2);
    print_flag("FAULTMASK:", cast(bool)vm.get_fault_mask(), flag_col_3);
    print_flag("PRIMASK:",               vm.get_pri_mask(), flag_col_4);

    // ============
    //  LOAD/STORE
    // ============

    auto latest_load_store = vm.get_latest_load_store();
    append_unique(load_store_buffer, latest_load_store, load_store_height - 5);

    mvwprintw(load_store_pad, load_store_y++, load_store_x, "Load/Store:");
    foreach (s; load_store_buffer) {
        mvwprintw(load_store_pad, load_store_y++, load_store_x, toStringz(s));
    }

    int screen_row     =  0;
    int col            =  1;
    int current_pc_row = -1;

    int pc_r = 0;
    foreach (r; rows) {
        if (r.addr == vm.get_pc()) {
            current_pc_row = pc_r;
        }
        pc_r++;
    }

    if (pc_moved) {
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
    }

    for (int j = start; j < end; ++j) {
        auto r = rows[j];
        if (r.type == row_view.kind.func_name) 
            mvwprintw(instr_pad, screen_row++, col, toStringz(r.s));
        if (r.type == row_view.kind.instr) {
            if (r.addr == vm.get_pc()) {
                wattron(instr_pad, A_REVERSE);
                current_pc_row = j;
                mvwprintw(instr_pad, screen_row++, col, toStringz(r.s));
                wattroff(instr_pad, A_REVERSE);
            } else
            print_colored_line(instr_pad, screen_row++, col, r.s);
        }
        if (r.type == row_view.kind.blank_line) 
            screen_row++;
    }

    wnoutrefresh(stdscr);
    prefresh(
        load_store_pad,
        0,                                                                                        0,
        load_store_screen_row,                                                load_store_screen_col,
        load_store_screen_row + load_store_height - 1, load_store_screen_col + load_store_width - 1
    );
    prefresh(
        reg_pad,
        0,                                                            0,                     
        reg_screen_row,                                  reg_screen_col,   
        reg_screen_row + reg_height - 1, reg_screen_col + reg_width - 1 
    );
    prefresh(
        flag_pad,
        0,                                                                0,                     
        flag_screen_row,                                    flag_screen_col,   
        flag_screen_row + flag_height - 1, flag_screen_col + flag_width - 1 
    );
    wnoutrefresh(instr_pad_frame);
    prefresh(instr_pad,
             0,                                         0,          
             frame_y + 1,                     frame_x + 1,     
             frame_y + frame_h - 2, frame_x + frame_w - 2  
    );
    doupdate();
}

void draw_screen_1(vm_t)(ref vm_t vm, const ref row_view[] rows) {
    werase(scb_pad);
    box(scb_pad, 0, 0);
    int scb_pad_y = 1;
    void print_reg(REG_T)(const string reg_name, ref int y, ref vm_t vm, REG_T r) {
        immutable val = vm.peek_word(r);
        int color = color_for_value(val, vm);    
        wattron(scb_pad, COLOR_PAIR(color));
        mvwprintw(scb_pad, y++, 1, toStringz(format("%s %08X", reg_name, val)));
        wattroff(scb_pad, COLOR_PAIR(color));
    }
    mvwprintw(scb_pad, scb_pad_y++, 1, toStringz("System Control Block"));
    print_reg("VTOR:    ", scb_pad_y, vm, VTOR);
    print_reg("CCR:     ", scb_pad_y, vm, CCR);
    print_reg("ICSR:    ", scb_pad_y, vm, ICSR);
    print_reg("SHPR1:   ", scb_pad_y, vm, SHPR1);
    print_reg("SHPR2:   ", scb_pad_y, vm, SHPR2);
    print_reg("SHPR3:   ", scb_pad_y, vm, SHPR3);
    print_reg("SHCSR:   ", scb_pad_y, vm, SHCSR);
    print_reg("MPU_TYPE:", scb_pad_y, vm, MPU_TYPE);
    print_reg("MPU_CTRL:", scb_pad_y, vm, MPU_CTRL);
    print_reg("MPU_RNR: ", scb_pad_y, vm, MPU_RNR);
    print_reg("MPU_RBAR:", scb_pad_y, vm, MPU_RBAR);
    print_reg("MPU_RASR:", scb_pad_y, vm, MPU_RASR);
    print_reg("SYST_CSR:", scb_pad_y, vm, SYST_CSR);
    print_reg("SYST_RVR:", scb_pad_y, vm, SYST_RVR);
    print_reg("SYST_CVR:", scb_pad_y, vm, SYST_CVR);
    mvwprintw(scb_pad, scb_pad_y++, 1, toStringz(format("BASEPRI:  %08X", vm.get_basepri())));

    //import std.algorithm.iteration : map;
    //import std.algorithm.searching : maxElement;
//
    //auto max_len = z_vars
    //    .map!(v => v.name.length)
    //    .maxElement;
    //foreach (v; z_vars) {
    //    auto name = format("%-*s", max_len + 1, v.name ~ ":");
    //    print_reg(name, scb_pad_y, vm, v.addr);
    //}
//
    //auto c_max_len = z_configs
    //    .map!(c => c.name.length)
    //    .maxElement;
    //foreach (c; z_configs) {
    //    auto name = format("%-*s", c_max_len + 1, c.name ~ ":");
    //    mvwprintw(scb_pad, scb_pad_y++, 1, toStringz(format("%s %u", name, c.addr)));
    //}

    prefresh(
        scb_pad,
        0, 0,            
        0, 0,           
        LINES - 1, COLS - 1  
    );

    doupdate();
}

void draw_screen(vm_t)(ref vm_t vm, const ref row_view[] rows) {
    if (view_changed) {
        view_changed = false;
        erase();
    }
    if (view_n == 0)
        draw_screen_0(vm, rows);
    else 
        draw_screen_1(vm, rows);
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

void control_loop(VM_T)(ref runtime_ctrl ctrl, ref VM_T vm, ref row_view[] rows) {
    int ch;
    while (true) {
        ch = getch();

        if (ch != ERR) {
            if (ch == 'q') {
                break;
            }
            if (ch == 'z') {
                pc_moved = false;
                start = max(0, start - 1);
                end   = start + visible_lines;
            }
            if (ch == 'x') {
                pc_moved = false;
                end   = min(cast(uint)rows.length, end + 1);
                start = end - visible_lines;
            }
            if (ch == KEY_DOWN) {
                vm.execute_next_instr();
                pc_moved = true;
            }
            if (ch == KEY_RIGHT) {
                if (view_n == 0) 
                    view_n = 1;
                else
                    view_n = 0;
                view_changed = true;
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
                pc_moved = true;
                ctrl.last_time = now;
            }
        }
        draw_screen(vm, rows);
    }
}

void load_elf(vm_t)(ref vm_t vm, soc mcu, const string target_file_name) {
    auto f_s        = get_program_from_elf(target_file_name);
    auto entry_addr = get_elf_entry_point(target_file_name);
    vm.init_pc(entry_addr);
    foreach (f; f_s) {
        load_function_into_memory(f, vm);
        vm.current_program ~= f.instrs;
        vm.func_names ~= f.name;
    }
    foreach (t; table_names) {
        load_section_into_memory(target_file_name, t, vm);
    }
    vm.objects  = get_st_name_val(target_file_name, st_type.stt_func,   mcu);
    vm.func_map = get_st_name_val(target_file_name, st_type.stt_func,   mcu,  false, true);
    vm.objects ~= get_st_name_val(target_file_name, st_type.stt_notype, mcu);
    vm.objects ~= get_st_name_val(target_file_name, st_type.stt_object, mcu);
}

void main(string[] args) {
    auto ctrl           = runtime_ctrl();
    ctrl.last_time      = MonoTime.currTime;
    ctrl.interval       =   dur!"msecs"(30);
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

    z_vars    = get_z_vars(target_file_name);
    z_configs = get_z_configs(target_file_name);

    if (args.length > 2) {
        soc_s = args[2];
    }

    if (soc_s != "nrf" && soc_s != "stm32" && soc_s != "nxp") {
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

    uint nth_instance = 0;
    if (args.length > 4) {
        try {
            nth_instance = to!uint(args[4], 16);
        } catch (ConvException e) {
            writeln("Invalid nth instance: ", args[4]);
            return;
        }
    }

    func[] f_s;
    f_s = get_program_from_elf(target_file_name);
    auto rows = generate_instr_rows(f_s);

    initscr();
    init_frames();
    curs_set(0);
    start_color();
    use_default_colors();

    start_color();
    //init_color(COLOR_WHITE,  970, 970, 950);
    init_color(COLOR_WHITE,  992, 964, 890);
    init_color(COLOR_CYAN,   400, 850, 940);
    init_color(COLOR_YELLOW, 900, 860, 450);
    init_color(COLOR_GREEN,  650, 880, 180);
    init_color(COLOR_RED,    980, 150, 450);
    init_color(8,            500, 500, 500);
    init_color(9,            248, 248, 248);

    init_color(10, 152, 545, 824);  
    init_color(11, 710, 537, 0);    
    init_color(12, 533, 600, 0);    
    init_color(13, 862, 196, 180);  

    short bg_color = COLOR_BLACK;
    short fg_color = COLOR_WHITE;
    init_pair(1, fg_color,     bg_color); 

    if (bg_color == COLOR_BLACK) {
        init_pair(2, COLOR_CYAN,   bg_color); 
        init_pair(3, COLOR_YELLOW, bg_color); 
        init_pair(4, COLOR_GREEN,  bg_color); 
        init_pair(5, COLOR_RED,    bg_color);
    } else {
        init_pair(2, 10, COLOR_WHITE);
        init_pair(3, 11, COLOR_WHITE);
        init_pair(4, 12, COLOR_WHITE);
        init_pair(5, 13, COLOR_WHITE);
    }
    init_pair(6, COLOR_WHITE,         8);
    init_pair(7, COLOR_WHITE,         9); 

    wbkgd(stdscr, COLOR_PAIR(1));
    wclear(stdscr);
    wrefresh(stdscr);
    
    scope(exit) endwin();
    cbreak();
    noecho();
    keypad(stdscr, true);

    timeout(20);

    instr_pad_frame = newwin(frame_h, frame_w, frame_y, frame_x);

    reg_pad        = newpad(            19, COLS / 2 - 2);
    flag_pad       = newpad(             6, COLS / 2 - 2);
    instr_pad      = newpad(         10000,          200);
    load_store_pad = newpad(    LINES - 27, COLS / 2 - 2);
    scb_pad        = newpad(         LINES,         COLS);

    wbkgd(reg_pad,        COLOR_PAIR(1));
    wbkgd(flag_pad,       COLOR_PAIR(1));
    wbkgd(instr_pad,      COLOR_PAIR(1));
    wbkgd(load_store_pad, COLOR_PAIR(1));
    wbkgd(scb_pad,        COLOR_PAIR(1));
    wbkgd(instr_pad_frame,COLOR_PAIR(1));

    box(reg_pad,         0, 0);
    box(flag_pad,        0, 0);
    box(instr_pad_frame, 0, 0);
    box(load_store_pad,  0, 0);
    box(scb_pad,         0, 0);

    if (soc_s == "nrf") {
        cortex_m_vm!nrf52840_mem vm;
        load_elf(vm, soc.nrf, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, rows);
        control_loop(ctrl, vm, rows);
    } else if (soc_s == "stm32") {
        cortex_m_vm!stm32f4_mem vm;
        vm.set_vtor();
        load_elf(vm, soc.stm32, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, rows);
        control_loop(ctrl, vm, rows);
    } else {
        cortex_m_vm!rw612_mem vm;
        vm.set_vtor();
        load_elf(vm, soc.nxp, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, rows);
        control_loop(ctrl, vm, rows);
    }

    endwin();
}

