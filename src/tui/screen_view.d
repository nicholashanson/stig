import reg_view;
import flag_view;
import instr_view;
import load_store_view;
import thumb_2_convert_instr_to_string;
import cortex_m_core;
import deimos.ncurses;
import std.algorithm;
import std.string   : toStringz;
import scb_defs;
import std.format;
import control_loop;
import core.thread : Thread;
import core.time   : msecs;
import std.range;

// --------------------------------------------------------------------------------------
// ===============
//  DRAW SCREEN 0
// ===============

void 
draw_screen_0
(vm_t)
(ref vm_t vm, ref runtime_ctrl ctrl, ref screen_t s, const ref row_view[] rows) {
    werase(s.load_store.load_store_pad);
    box(s.load_store.load_store_pad, 0, 0);
    box(s.instr.instr_pad_frame, 0, 0);
    bool instr_pad_moved = false;
    s.reg.draw(ctrl, vm);
    s.flag.draw_flags(vm);
    s.load_store.draw(vm);
    s.instr.draw(ctrl, vm.get_pc(), rows);
    s.refresh_screen();
    ctrl.first_draw = false;
    ctrl.instr_view_changed = false;
}
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// ===============
//  DRAW SCREEN 1
// ===============

void 
draw_screen_1
(vm_t)
(ref vm_t vm, ref runtime_ctrl ctrl, ref screen_t s, const ref row_view[] rows) {
    werase(s.scb_pad);
    box(s.scb_pad, 0, 0);
    int scb_pad_y = 1;
    void print_reg(REG_T)(const string reg_name, ref int y, ref vm_t vm, REG_T r) {
        immutable val = vm.peek_word(r);
        int color = vm.get_val_index(val);    
        wattron(s.scb_pad, COLOR_PAIR(color));
        mvwprintw(s.scb_pad, y++, 1, toStringz(format("%s %08X", reg_name, val)));
        wattroff(s.scb_pad, COLOR_PAIR(color));
    }
    mvwprintw(s.scb_pad, scb_pad_y++, 1, toStringz("System Control Block"));
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
    mvwprintw(s.scb_pad, scb_pad_y++, 1, toStringz(format("BASEPRI:  %08X", vm.get_basepri())));

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
        s.scb_pad,
        0, 0,            
        0, 0,           
        LINES - 1, COLS - 1  
    );

    doupdate();
}
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// =============
//  DRAW SCREEN
// =============

void 
draw_screen
(vm_t)
(ref vm_t vm, ref runtime_ctrl ctrl, ref screen_t s, const ref row_view[] rows) {
    if (ctrl.view_changed) {
        ctrl.view_changed = false;
        erase();
    }
    return (s.view_n == 0) ? draw_screen_0(vm, ctrl, s, rows)
                           : draw_screen_1(vm, ctrl, s, rows);
} 
// --------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------
// ==============
//  CONTROL LOOP
// ==============

void 
ctrl_loop
(vm_t)
(ref runtime_ctrl ctrl, ref screen_t s, ref vm_t vm, ref row_view[] rows) {
    int ch;
    while (true) {
        ch = getch();
        if (ch != ERR) {
            switch (ch) {
                case 'q': 
                    break;
                case 'z':
                    ctrl.move();
                    s.instr.start = max(0, s.instr.start - 1);
                    s.instr.end   = s.instr.start + s.instr.visible_lines;
                    break;
                case 'x':
                    ctrl.move();
                    s.instr.end   = min(cast(uint)rows.length, s.instr.end + 1);
                    s.instr.start = s.instr.end - s.instr.visible_lines; 
                    break;
                case KEY_DOWN:
                    vm.advance_to_next_cycle();
                    ctrl.hold_key_down();
                    break;
                case KEY_RIGHT:
                    s.view_n = (s.view_n == 0) ? 1 : 0;
                    ctrl.change_view();
                    break;
                case ' ': 
                    ctrl.toggle_play();
                    break;
                default:
                    break;
            }        
        }
        if (ctrl.is_playing)
            if (ctrl.pc_advance_is_due()) 
                vm.advance_to_next_cycle();
        if (ctrl.dirty) 
            draw_screen(vm, ctrl, s, rows);
        if (!ctrl.key_down)
            Thread.sleep(10.msecs);
        ctrl.reset_flags();
    }
}
// --------------------------------------------------------------------------------------