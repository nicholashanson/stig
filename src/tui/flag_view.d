import deimos.ncurses;
import line;
import std.format;

struct flag_panel {
	WINDOW* flag_pad;

	int flag_screen_row;   
    int flag_screen_col = 1;   
    int flag_height     = 8;     
    int flag_width;
    int flag_y     = 1;
    int flag_x     = 1;
    int flag_col_1 = 1;
    int flag_col_2;
    int flag_col_3;
    int flag_col_4;
    bool first_flag = true;

    void init(int reg_height) {
    	flag_screen_row =  reg_height - 1;    
		flag_width      =  COLS / 2 - 2;
		flag_col_2      =  flag_width      / 4;
		flag_col_3      =  flag_width      / 2;
		flag_col_4      = (flag_width / 4) * 3; 
    }

    void 
    print_flag
    (string name, bool val, const int flag_x_) {
        int color  = val ? 4 : 1;
        if (!first_flag && (flag_x_ == 1)) {
            ++flag_y;
        } else {
            first_flag = false;
        }
        print_string(flag_pad, flag_y, flag_x_, format("%s %d", name, val), color);
    };

    void 
    draw_flags
    (vm_t)
    (ref vm_t vm) {
    	flag_y = 1;
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
	    first_flag = true;
    }

    void refresh() {
	    prefresh(
	        flag_pad,
	        0,                                                                0,                     
	        flag_screen_row,                                    flag_screen_col,   
	        flag_screen_row + flag_height - 1, flag_screen_col + flag_width - 1 
	    );
	}
}