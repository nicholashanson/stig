import line;
import cortex_m_core;
import vm;
import deimos.ncurses;
import thumb_2_convert_instr_to_string;
import std.array : replicate;
import std.format;
import std.algorithm : canFind;
import std.string : toStringz;
import control_loop;

string[16] reg_pad_str = ["r0: ", "r1: ", "r2: ", "r3: ", "r4: ", "r5: ",                        
                          "r6: ", "r7: ", "r8: ", "r9: ", "r10:", "r11:",                        
                          "r12:", "sp: ", "lr: ", "pc: "];                        
// --------------------------------------------------------------------------------------

struct reg_panel {
    WINDOW* reg_pad;
    int     reg_screen_row   =            1;  
    int     reg_screen_col   =            1;   
    int     reg_height       =           21;    
    int     reg_width;
    int     reg_x        = 1;
    int     reg_y        = 1;
    int     reg_y_base;

    void init() {    
        reg_width = COLS / 2 - 2; 
    }

    void
    print_reg
    (vm_t)
    (string name, reg r, ref vm_t vm) {
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
        int color = vm.get_val_index(val);
        print_string(reg_pad, reg_y++, reg_x, format("%s %08X %s", name, val, reg_name), color);
    };

    void 
    print_reg_at
    (vm_t)
    (string name, reg r, ref vm_t vm) {
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
        int color = vm.get_val_index(val);
        print_string(reg_pad, reg_y_base + cast(int)r, reg_x, format("%s %08X %s", name, val, reg_name), color);
    };

    void draw
    (vm_t)
    (ref runtime_ctrl ctrl, ref vm_t vm) {
        reg_y = 1;
        if (ctrl.first_draw) {
            mvwprintw(reg_pad, reg_y++, reg_x, "Core Registers:");
            for (int i = 0; i < 16; ++i) {
                print_reg(reg_pad_str[i], cast(reg)i, vm);
            }
        } else {
            reg_y++;
            reg_y_base = reg_y;
            foreach (r; vm.last_instr.touched_regs) {
                if (r == reg.none)
                    break;
                print_reg_at(reg_pad_str[cast(ubyte)r], r, vm);
            }
            reg_y = reg_y_base + 16;
        }
    }

    void refresh() {
        prefresh(
            reg_pad,
            0,                                                            0,                     
            reg_screen_row,                                  reg_screen_col,   
            reg_screen_row + reg_height - 1, reg_screen_col + reg_width - 1 
        );
    }
}

// --------------------------------------------------------------------------------------
// ====================
//  PRINT COLORED LINE
// ====================

void print_colored_reg_line(WINDOW* win, int row, int col, string line) {
    auto tokens = split_instr_line(line);
    int x = col;
    foreach (t; tokens) {
        if (regs.canFind(t)) 
            print_string(win, row, x, t, 3);
        else 
            mvwprintw(win, row, x, toStringz(t));
        x += t.length; 
    }
}
// --------------------------------------------------------------------------------------