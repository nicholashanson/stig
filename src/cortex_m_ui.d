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

// Global pad and scroll offset:
WINDOW* instrPad;
WINDOW* regPad;
WINDOW* flagPad;
WINDOW* stackPad;
int padPos = 0;
bool regBoxView = false;

void drawBitBox(WINDOW* win, int y, int x, bool setBit) {
    if (setBit)
        wattron(win, COLOR_PAIR(1));
    else
        wattron(win, COLOR_PAIR(2));

    mvwprintw(win, y, x, " ");

    if (setBit)
        wattroff(win, COLOR_PAIR(1));
    else
        wattroff(win, COLOR_PAIR(2));
}

void drawRegisterBoxes(
    WINDOW* win,
    int y,
    int x,
    string name,
    uint value
) {
    // label
    wattron(win, COLOR_PAIR(3));
    mvwprintw(win, y, x, toStringz(name ~ ":"));
    wattroff(win, COLOR_PAIR(3));

    int bitX = cast(int)(x + name.length + 2);

    foreach (i; 0 .. 32) {
        int bit = 31 - i;
        bool setBit = ((value >> bit) & 1) != 0;
        drawBitBox(win, y, bitX + i, setBit);
    }
}

void draw_register_box_view(cortex_m_vm vm) {
    int y = 0;
    int x = 0;

    drawRegisterBoxes(stdscr, y++, x, "r0 ", vm.cpu.r0);
    drawRegisterBoxes(stdscr, y++, x, "r1 ", vm.cpu.r1);
    drawRegisterBoxes(stdscr, y++, x, "r2 ", vm.cpu.r2);
    drawRegisterBoxes(stdscr, y++, x, "r3 ", vm.cpu.r3);
    drawRegisterBoxes(stdscr, y++, x, "r4 ", vm.cpu.r4);
    drawRegisterBoxes(stdscr, y++, x, "r5 ", vm.cpu.r5);
    drawRegisterBoxes(stdscr, y++, x, "r6 ", vm.cpu.r6);
    drawRegisterBoxes(stdscr, y++, x, "r7 ", vm.cpu.r7);
    drawRegisterBoxes(stdscr, y++, x, "r8 ", vm.cpu.r8);
    drawRegisterBoxes(stdscr, y++, x, "r9 ", vm.cpu.r9);
    drawRegisterBoxes(stdscr, y++, x, "r10", vm.cpu.r10);
    drawRegisterBoxes(stdscr, y++, x, "r11", vm.cpu.r11);
    drawRegisterBoxes(stdscr, y++, x, "r12", vm.cpu.r12);
    drawRegisterBoxes(stdscr, y++, x, "sp ", vm.cpu.get_sp());
    drawRegisterBoxes(stdscr, y++, x, "lr ", vm.cpu.lr);
    drawRegisterBoxes(stdscr, y++, x, "pc ", vm.cpu.pc);

    y++;
    drawRegisterBoxes(stdscr, y++, x, "Z   ", vm.cpu.z ? 1u : 0u);
    drawRegisterBoxes(stdscr, y++, x, "N   ", vm.cpu.n ? 1u : 0u);
    drawRegisterBoxes(stdscr, y++, x, "C   ", vm.cpu.c ? 1u : 0u);
    drawRegisterBoxes(stdscr, y++, x, "V   ", vm.cpu.v ? 1u : 0u);
}

int color_for_value(uint val, ref cortex_m_vm vm) {
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

void draw_screen(cortex_m_vm vm, func[] functions, bool key_press) {
    static uint previous_pc = 0;
    if (vm.cpu.pc != previous_pc) {
        //clear(); // clear screen
    }
    // ----------------------------
    // Left pane: registers
    // ----------------------------
    if (regBoxView) {
        draw_register_box_view(vm);
    } else { 
        int regX = 0;
        int regY = 0;
        int flagY = 0;
        int stackY = 0;
        int stackX = 0;

        auto printReg = (string name, uint val, ref cortex_m_vm vm) {
            auto f = access_log();
            string reg_name = vm.mem.get_reg_name(val);
            if (reg_name == "") {
                foreach (e; vm.objects) {
                if (e.addr == val) {
                        reg_name = e.name;
                        break;
                    }
                }
            }
            if (reg_name == "") 
                reg_name = "                                                     ";
            else {
                f.writeln(reg_name);
                f.flush();
                reg_name ~= "               ";
            }
            int color = color_for_value(val, vm);
            wattron(regPad, COLOR_PAIR(color));
            mvwprintw(regPad, regY++, regX, toStringz(format("%s %08x %s", name, val, reg_name)));
            wattroff(regPad, COLOR_PAIR(color));
        };
        auto printFlag = (string name, bool val) {
            mvwprintw(flagPad, flagY++, regX, toStringz(format("%s %d", name, val)));
        };

        mvwprintw(regPad, regY++, regX, "Core Registers:");
        printReg("r0: ", vm.cpu.r0, vm);
        printReg("r1: ", vm.cpu.r1, vm);
        printReg("r2: ", vm.cpu.r2, vm);
        printReg("r3: ", vm.cpu.r3, vm);
        printReg("r4: ", vm.cpu.r4, vm);
        printReg("r5: ", vm.cpu.r5, vm);
        printReg("r6: ", vm.cpu.r6, vm);
        printReg("r7: ", vm.cpu.r7, vm);
        printReg("r8: ", vm.cpu.r8, vm);
        printReg("r9: ", vm.cpu.r9, vm);
        printReg("r10:", vm.cpu.r10, vm);
        printReg("r11:", vm.cpu.r11, vm);
        printReg("r12:", vm.cpu.r12, vm);
        printReg("sp: ", vm.cpu.get_sp(), vm);
        printReg("lr: ", vm.cpu.lr, vm);
        printReg("pc: ", vm.cpu.pc, vm);
        printReg("CONTROL:", vm.cpu.get_control_reg(), vm);
        mvwprintw(flagPad, flagY++, regX, "Flags:");
        printFlag("z:", vm.cpu.z);
        printFlag("n:", vm.cpu.n);
        printFlag("c:", vm.cpu.c);
        printFlag("v:", vm.cpu.v);
        printFlag("ge0:", vm.cpu.ge0);
        printFlag("ge1:", vm.cpu.ge1);
        printFlag("ge2:", vm.cpu.ge2);
        printFlag("ge3:", vm.cpu.ge3);
        flagY++;
        printFlag("SPSEL:", vm.cpu.sp_sel);
        printFlag("NPRIV:", vm.cpu.npriv);
        printFlag("FAULTMASK:", vm.cpu.fault_mask);
        printFlag("PRIMASK:", vm.cpu.pri_mask);
        mvwprintw(flagPad, flagY++, regX, toStringz(format("BASEPRI: %08x", vm.cpu.basepri)));
        mvwprintw(flagPad, flagY++, regX, toStringz(format("USART1 DR: %08x", vm.mem.read_word(0x0800a280)))); 
        flagY++;
        mvwprintw(flagPad, flagY++, regX, toStringz(format("Tick: %d", vm.cpu.tick)));
        
        regY++;
        mvwprintw(stackPad, stackY++, stackX, "Stack:");
        if (vm.cpu.get_sp() != 0) {
            uint ptr = vm.cpu.get_sp();
            while (ptr < vm.mem.stack_base) {
                uint val = vm.mem.read_word(ptr);
                mvwprintw(stackPad, stackY++, stackX, toStringz(format("%08x: %08x", ptr, val)));
                ptr += 4;
            }
        }
        flagY++;
        mvwprintw(flagPad, flagY++, regX, "IT Stack:");
        foreach (item; vm.cpu.it_block_stack) {
            mvwprintw(flagPad, flagY++, regX, toStringz(format("%s", item.to!string)));
        }
    }

    int instrPadRow = 0;
    int instrPadCol = 0;
    int currentPcRow = 0; 

    bool pad_changed = key_press;
    if (true) { 
        //werase(instrPad);
        previous_pc = vm.cpu.pc;
        pad_changed = true;
        foreach (f; functions) {
            mvwprintw(instrPad, instrPadRow++, instrPadCol,
                          toStringz(format("%s", f.name)));
            foreach (ins; f.instrs) {
                string s;

                if (ins._addr == vm.cpu.pc) {
                    wattron(instrPad, A_REVERSE);
                    currentPcRow = instrPadRow;
                }

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
                    mvwprintw(instrPad, instrPadRow++, instrPadCol,
                              toStringz(format("%x: %s     %s", ins._addr, ins._instr_bytes, s)));
                } else {
                    mvwprintw(instrPad, instrPadRow++, instrPadCol,
                              toStringz(format("%x: %s         %s", ins._addr, ins._instr_bytes, s)));
                }

                if (ins._addr == vm.cpu.pc) {
                    wattroff(instrPad, A_REVERSE);
                }
            }
            instrPadRow++;
        }
    }

    int visibleLines = LINES;
    int bottomMargin = 5; // minimum lines below PC

    // Scroll up if PC is above view
    if (currentPcRow < padPos) {
        padPos = currentPcRow;
    }

    // Soft scroll down if PC is too close to bottom
    int distanceToBottom = padPos + visibleLines - currentPcRow - 1;
    if (distanceToBottom < bottomMargin) {
        padPos += bottomMargin - distanceToBottom; // scroll just enough to restore margin
    }

    // Draw pad into right side of screen
    int instrScreenX = 50;   // <-- visible position

    wnoutrefresh(stdscr);

    int regScreenRow = 0;   // top row to display registers
    int regScreenCol = 0;   // left column
    int regHeight = 18;     // number of rows visible
    int regWidth = 50;      // width of the pad

    int flagScreenRow = regHeight + 1;   
    int flagScreenCol = 0;   
    int flagHeight = 20;     
    int flagWidth = 25;

    int stackScreenRow = regHeight + 1;   
    int stackScreenCol = 50;   
    int stackHeight = 17;     
    int stackWidth = 25;

    prefresh(
        regPad,
        0, 0,                     // first line/col of pad to show
        regScreenRow, regScreenCol,   // top-left on screen
        regScreenRow + regHeight - 1, regScreenCol + regWidth - 1 // bottom-right on screen
    );
    prefresh(
        flagPad,
        0, 0,                     
        flagScreenRow, flagScreenCol,   
        flagScreenRow + flagHeight - 1, flagScreenCol + flagWidth - 1 
    );
    prefresh(
        stackPad,
        0, 0,                     
        stackScreenRow, stackScreenCol,   
        stackScreenRow + stackHeight - 1, stackScreenCol + stackWidth - 1 
    );
    prefresh(instrPad,
             padPos, 0,           // first line of pad to show
             0, COLS / 2 - 1,     // location on real screen
             LINES - 1, COLS - 1  // bottom-right of real screen
    );

    doupdate();

    //mvwprintw(stdscr, 0, 0, toStringz(format("%d: %d", LINES, COLS)));
}

void main(string[] args) {
    bool isPlaying = false;
    auto lastTime = MonoTime.currTime;       // last execution time
    auto interval = dur!"msecs"(20);
    auto lastDraw = MonoTime.currTime;
    auto frameInterval = dur!"msecs"(33); // ~30 FPS

    uint entryPoint = 0; 
    string objdump_file_name;

    if (args.length > 1) {
        objdump_file_name = args[1];
    }

    if (args.length > 2) {
        try {
            entryPoint = to!uint(args[2], 16);
        } catch (ConvException e) {
            writeln("Invalid entry point: ", args[2]);
            return;
        }
    }

    initscr();
    curs_set(0);
    start_color();
    use_default_colors();

    start_color();

    //init_color(COLOR_BLACK,  150, 160, 140);

    // Foreground
    init_color(COLOR_WHITE,  970, 970, 950);

    // Cyan
    init_color(COLOR_CYAN,   400, 850, 940);

    // Yellow
    init_color(COLOR_YELLOW, 900, 860, 450);

    // Green
    init_color(COLOR_GREEN,  650, 880, 180);

    // Red
    init_color(COLOR_RED,    980, 150, 450);

    init_pair(1, COLOR_WHITE,  COLOR_BLACK); 
    init_pair(2, COLOR_CYAN,   COLOR_BLACK); 
    init_pair(3, COLOR_YELLOW, COLOR_BLACK); 
    init_pair(4, COLOR_GREEN,  COLOR_BLACK); 
    init_pair(5, COLOR_RED,    COLOR_BLACK); 
    
    scope(exit) endwin();
    cbreak();
    noecho();
    keypad(stdscr, true);

    timeout(20);

    regPad = newpad(32, 50);
    flagPad = newpad(42, 25);
    stackPad = newpad(32, 25);
    instrPad = newpad(10000, 200);

    cortex_m_vm vm;
    if (!objdump_file_name.canFind("elf")) {
        vm.load_program(objdump_file_name);
    } else {
        auto f_h = load_store_log();
        f_h.writeln("Loading program");
        f_h.flush();
        auto f_s = get_program_from_elf(objdump_file_name);
        vm.cpu.pc = get_elf_entry_point(objdump_file_name) - 1;
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
            load_section_into_memory(objdump_file_name, t, vm.mem);
        }
        vm.objects = get_st_name_val(objdump_file_name, st_type.stt_func);
        vm.objects ~= get_st_name_val(objdump_file_name, st_type.stt_notype);
        vm.objects ~= get_st_name_val(objdump_file_name, st_type.stt_object);
    }

    auto file_mem = File("mem.txt", "w");
    for (size_t i = memory.flash_origin; i < memory.flash_origin + memory.flash_length; i += 4) {
        uint val = vm.mem.read_word(i);
        if (val != 0) {
            file_mem.writeln("PC = 0x", format("[%08X]: %08X", i, val));
        }
    }
    file_mem.close();

    func[] f_s;
    if (objdump_file_name == "../test/cortex_m_asm.txt") {
        foreach (name; bare_metal_func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else if (objdump_file_name == "../test/zephyr_thread_asm.txt") {
        foreach (name; zephyr_func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else if (objdump_file_name == "../test/freertos_no_task_asm.txt") {
        foreach (name; freertos_no_task) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else if (objdump_file_name == "../test/dsp_asm.txt") {
        foreach (name; dsp_func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else if (objdump_file_name == "../test/freertos_blink_asm.txt") {
        foreach (name; freertos_func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else if (objdump_file_name.canFind("elf")) {
        f_s = get_program_from_elf(objdump_file_name);
    } else {
        foreach (name; vm.func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    }

    if (entryPoint != 0) {
        vm.run_to(entryPoint);
    }

    bool key_press = false;
    draw_screen(vm, f_s, key_press);

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
            if (ch == 'z') { // scroll down
                padPos = min(padPos + 1, vm.current_program.length + (f_s.length * 2) - LINES);
                key_press = !key_press;
            }
            if (ch == 'x') { // scroll up
                padPos = max(padPos - 1, 0);
                key_press = !key_press;
            }
            if (ch == ' ') { 
                isPlaying = !isPlaying;
            }
            if (ch == 'b') {
                padPos = cast(int)(vm.current_program.length + (f_s.length * 2) - LINES);
            }
            if (ch == 'v') {
                regBoxView = !regBoxView;
            }
            if (ch == 'p') {
                vm.mem.flip_bit(0x40023800, 25);
            }  
            if (ch == 'y') {
                vm.mem.flip_bit(0x40023800, 27);
            }  
        }

        auto now = MonoTime.currTime;
        if (isPlaying) {
            auto delta = now - lastTime; // delta is already a Duration
            if (delta >= interval) {
                vm.execute_next_instr();
                lastTime = now;
            }
        }
        draw_screen(vm, f_s, key_press);
        /*
        if (now - lastDraw >= frameInterval) {
            
            lastDraw = now;
        }
        */
    }

    endwin();
}

