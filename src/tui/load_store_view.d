import deimos.ncurses;
import std.conv;
import line;
import thumb_2_convert_instr_to_string;
import std.range;
import std.algorithm;
import std.array : array;

// --------------------------------------------------------------------------------------
// ===============
//  APPEND UNIQUE
// ===============

void append_unique(ref string[] buffer, string next, size_t n) {
    if (next == "") 
        return;

    if (buffer.empty || buffer.back != next)
        buffer ~= next;
    while (buffer.length > n)
        buffer = buffer[1 .. $];
}

// ==================
//  LOAD STORE PANEL
// ==================

struct load_store_panel {
    WINDOW*  load_store_pad;
    int      load_store_screen_row;   
    int      load_store_screen_col = 1;   
    int      load_store_height;  
    int      load_store_width;
    int      load_store_x = 1;
    int      load_store_y = 1;
    string[] load_store_buffer;

    void init(int reg_height) {
        load_store_screen_row = reg_height + 5;
        load_store_height     =     LINES - 25;
        load_store_width      =   COLS / 2 - 2;
    }

    void 
    draw
    (vm_t)
    (ref vm_t vm) {
        load_store_y = 1;
        mvwprintw(load_store_pad, load_store_y++, load_store_x, "Load/Store:");
        if (vm.load_store_occured) {
            append_unique(load_store_buffer, vm.get_latest_load_store(), load_store_height - 5);
            foreach (s; load_store_buffer) 
                print_colored_load_store_line(load_store_pad, vm, load_store_y++, load_store_x, s);
        }
    }

    void refresh() {
        prefresh(
            load_store_pad,
            0,                                                                                        0,
            load_store_screen_row,                                                load_store_screen_col,
            load_store_screen_row + load_store_height - 1, load_store_screen_col + load_store_width - 1
        );
    }
}
// --------------------------------------------------------------------------------------
// =============
//  PRINT CHUNK
// =============

void 
print_chunk(WINDOW* win, 
            ref int x, 
            const int row,
            const int col, 
            const size_t max_len, 
            string v, 
            ref bool skip,
            const int color) 
{
    if (x + v.length > col + max_len - 1) {
        size_t delta  = x + v.length - 1 - col - max_len;
        int keep = cast(int)v.length - cast(int)delta - 3;
        if (keep <= 0) {
            int dots = max(0, 3 + keep); 
            v = ".".dup.repeat(dots).join;
        } else {
            v = v[0 .. keep] ~ "...";
        }
        skip = true;
    }
    print_string(win, row, x, v, color);
    x += v.length;
}
// --------------------------------------------------------------------------------------
// ===============================
//  PRINT COLORED LOAD STORE LINE
// ===============================

void 
print_colored_load_store_line
(vm_t)
(WINDOW* win, vm_t vm, int row, int col, string line) {
    size_t max_len = COLS / 2 - 5;
    auto tokens    = split_load_store_line(line);
    bool skip      = false;
    int x = col;
    for (int i = 0; i < tokens.length; ++i) {
        string v = tokens[i];
        if (skip)
            break;
        switch (i) {
            case 0: // tick
                print_chunk(win, x, row, col, max_len, v, skip, 2 /*color*/);
                break; 
            case 1: // pc
            case 2: // func name
                print_chunk(win, x, row, col, max_len, v, skip, 4 /*color*/);
                break;
            case 3: // src/dst
                print_string(win, row, x, "(", 0);
                x++;
                int color = 0;
                if (v[1] == 'x') {
                    uint val = to!uint(v[2 .. $], 16);
                    color = vm.get_val_index(val);
                }
                print_chunk(win, x, row, col, max_len, v, skip, color);
                break;
            case 4: // " loaded from "/" stored to "
                x++;
                print_chunk(win, x, row, col, max_len, v, skip, 0 /*color*/);
                x++;
                break;
            case 5: // src/dst
                int color = 0;
                if (v[1] == 'x') {
                    uint val = to!uint(v[2 .. $], 16);
                    color = vm.get_val_index(val);
                }
                print_chunk(win, x, row, col, max_len, v, skip, color);
                break;
            case 6: // register name
                if (v.length > 0)
                    print_chunk(win, x, row, col, max_len, v, skip, 5 /*color*/);
                if (skip)
                    continue;
                print_string(win, row, x, ")", 0);
                break;
            default:
                break;
        }
    }
}
// --------------------------------------------------------------------------------------