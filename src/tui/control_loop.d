import core.thread : Thread;
import core.time   : msecs;
import core.time   : MonoTime, dur;
import std.datetime;
import thumb_2_convert_instr_to_string;
import deimos.ncurses;

import reg_view;
import flag_view;
import instr_view;
import load_store_view;
import std.algorithm;

int frame_h;
int frame_w;
int frame_y;
int frame_x;

struct screen_t {
    reg_panel        reg;
    instr_panel      instr;
    flag_panel       flag;
    load_store_panel load_store;
    int view_n         =  0;
    WINDOW* scb_pad;

    void init() {
        reg.init();
        load_store.init(reg.reg_height);
        flag.init(reg.reg_height);
    }

    void init_pads() {
        instr.instr_pad_frame     = newwin(frame_h, frame_w, frame_y, frame_x);
        reg.reg_pad               = newpad(        19, COLS / 2 - 2);
        flag.flag_pad             = newpad(         6, COLS / 2 - 2);
        instr.instr_pad           = newpad(     10000,          200);
        load_store.load_store_pad = newpad(LINES - 27, COLS / 2 - 2);
        scb_pad                   = newpad(     LINES,         COLS);
    }

    void set_bkgd() {
        wbkgd(reg.reg_pad,               COLOR_PAIR(1));
        wbkgd(flag.flag_pad,             COLOR_PAIR(1));
        wbkgd(instr.instr_pad,           COLOR_PAIR(1));
        wbkgd(load_store.load_store_pad, COLOR_PAIR(1));
        wbkgd(scb_pad,                   COLOR_PAIR(1));
        wbkgd(instr.instr_pad_frame,     COLOR_PAIR(1));
    }

    void draw_boxes() {
        box(reg.reg_pad,                0, 0);
        box(flag.flag_pad,              0, 0);
        box(instr.instr_pad_frame,      0, 0);
        box(load_store.load_store_pad,  0, 0);
        box(scb_pad,                    0, 0);
    }

    void refresh_screen() {
        wnoutrefresh(stdscr);
        reg.refresh();
        instr.refresh();
        flag.refresh();
        load_store.refresh();
        doupdate();
    }
}

// --------------------------------------------------------------------------------------
// ==============
//  RUNTIME CTRL
// ==============

struct runtime_ctrl {
    bool     is_playing         = false;
    bool     dirty              = false;
    bool     key_down           = false;
    bool     pc_moved           = true;
    bool     instr_view_changed = false;
    bool     view_changed       = false;
    bool     first_draw         = true;
    MonoTime last_time;
    Duration interval;       
    MonoTime last_draw;
    Duration frame_interval; 

    void move() {
        instr_view_changed = true;
        dirty              = true;
    }

    void advance_pc() {
        pc_moved = true;
        dirty    = true;
    }

    void hold_key_down() {
        advance_pc();
        key_down = true;
    }

    void touch() {
        dirty = true;
    }

    void change_view() {
        view_changed = true;
        dirty = true;
    }

    bool pc_advance_is_due() {
        auto now   = MonoTime.currTime;
        auto delta = now - last_time;
        if (delta >= interval) {
            advance_pc();
            last_time = now;
            return true;
        }
        return false;
    }

    void toggle_play() {
        is_playing = !is_playing;
        touch();
    }

    void reset_flags() {
        dirty              = false;
        key_down           = false;
        pc_moved           = false;
        instr_view_changed = false;
        view_changed       = false;
    }
}
// --------------------------------------------------------------------------------------