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
import core.thread : Thread;
import core.time   : msecs;

import vm;
import cortex_m_core;
import memory_sections;
import parse_elf;
import thumb_2_instrs;
import thumb_2_decode_instr;
import thumb_2_execute_instr;
import thumb_2_convert_instr_to_string;
import scb_defs;
import elf_table_names;

import screen_view;
import control_loop;

st_name_val[] z_vars;
st_name_val[] z_configs;

int speed = 0;

void init_frames() {
    frame_h =    LINES - 2;
    frame_w =     COLS / 2;
    frame_y =            1;
    frame_x =     COLS / 2;
}

screen_t ui;

// --------------------------------------------------------------------------------------

// ===============
//  DRAW SCREEN 0
// ===============

// --------------------------------------------------------------------------------------
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
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// ==================
//  GET SECTION SIZE
// ==================

void get_section_size(const string elf_filename, const string section_name) {
    auto section = get_section_by_name(elf_filename, section_name);
    writeln(format("%s size: %d", section.name, section.data.length));
}
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// ==========
//  LOAD ELF
// ==========

void load_elf_(vm_t)(ref vm_t vm, soc mcu, const string target_file_name) {
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

void load_elf(vm_t)(ref vm_t vm, soc mcu, const string target_file_name) {
    auto e          = new elf_file(target_file_name);
    auto funcs      = get_program_from_elf(e);
    auto entry_addr = e.get_elf_entry_point();
    vm.init_pc(entry_addr);            
    assert(funcs.length != 0);
    foreach (fun; funcs) {
        load_function_into_memory(fun, vm);
        vm.current_program ~= fun.instrs;
        vm.func_names ~= fun.name;
    }
    assert(vm.current_program.length != 0);
    foreach (t; table_names) 
        load_section_into_memory(target_file_name, t, vm);
    vm.objects  = get_st_name_val(e, st_type.stt_func,   mcu);
    vm.func_map = get_st_name_val(e, st_type.stt_func,   mcu,  false, true);
    vm.objects ~= get_st_name_val(e, st_type.stt_notype, mcu);
    vm.objects ~= get_st_name_val(e, st_type.stt_object, mcu);
}
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// ======
//  MAIN
// ======

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

    if (soc_s != "nrf" && soc_s != "stm32" && soc_s != "nxp" && soc_s != "s32k16") {
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
    //init_color(COLOR_WHITE,  970, 970, 950)l
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

    ui.init();
    ui.init_pads();
    ui.set_bkgd();
    ui.draw_boxes();

    if (soc_s == "nrf") {
        cortex_m_vm!nrf52840_mem vm;
        load_elf(vm, soc.nrf, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, ctrl, ui, rows);
        ctrl_loop(ctrl, ui, vm, rows);
    } else if (soc_s == "stm32") {
        cortex_m_vm!stm32f4_mem vm;
        vm.set_vtor();
        load_elf(vm, soc.stm32, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, ctrl, ui, rows);
        ctrl_loop(ctrl, ui, vm, rows);
    } else if (soc_s == "s32k16") {
        cortex_m_vm!s32k146_mem vm;
        vm.set_vtor();
        load_elf(vm, soc.s32k16, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, ctrl, ui, rows);
        ctrl_loop(ctrl, ui, vm, rows);
    } else {
        cortex_m_vm!rw612_mem vm;
        vm.set_vtor();
        load_elf(vm, soc.nxp, target_file_name);
        if (entry_point != 0)
            vm.run_to(entry_point, nth_instance);
        draw_screen(vm, ctrl, ui, rows);
        ctrl_loop(ctrl, ui, vm, rows);
    }

    endwin();
}
// --------------------------------------------------------------------------------------


