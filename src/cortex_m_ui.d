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

// Global pad and scroll offset:
WINDOW* instrPad;
int padPos = 0;

void draw_screen(cortex_m_vm vm, func[] functions, bool key_press) {
    static uint previous_pc = 0;
    if (vm.cpu.pc != previous_pc) {
        //clear(); // clear screen
    }
    // ----------------------------
    // Left pane: registers
    // ----------------------------
    int regX = 0;
    int regY = 0;

    auto printReg = (string name, uint val) {
        mvwprintw(stdscr, regY++, regX, toStringz(format("%s: %08x", name, val)));
    };

    printReg("r0", vm.cpu.r0);
    printReg("r1", vm.cpu.r1);
    printReg("r2", vm.cpu.r2);
    printReg("r3", vm.cpu.r3);
    printReg("r4", vm.cpu.r4);
    printReg("r5", vm.cpu.r5);
    printReg("r6", vm.cpu.r6);
    printReg("r7", vm.cpu.r7);
    printReg("r8", vm.cpu.r8);
    printReg("r9", vm.cpu.r9);
    printReg("r10", vm.cpu.r10);
    printReg("r11", vm.cpu.r11);
    printReg("r12", vm.cpu.r12);
    printReg("sp", vm.cpu.sp);
    printReg("lr", vm.cpu.lr);
    printReg("pc", vm.cpu.pc);

    regY++;
    if (vm.cpu.sp != 0) {
        uint ptr = vm.cpu.sp;
        while (ptr < vm.mem.stack_base) {
            uint val = vm.mem.read_word(ptr);
            mvwprintw(stdscr, regY++, regX, toStringz(format("%08x: %08x", ptr, val)));
            ptr += 4;
        }
    }

    // ----------------------------
    // Right pane: instructions ON PAD
    // ----------------------------
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
                        s ~= format("#[%8x]", base + i16.imm);
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

    if (true) {
        refresh();
        prefresh(instrPad,
                 padPos, 0,           // first line of pad to show
                 0, COLS / 2 - 1,     // location on real screen
                 LINES - 1, COLS - 1  // bottom-right of real screen
        );
    }

    //mvwprintw(stdscr, 0, 0, toStringz(format("%d: %d", LINES, COLS)));
}

void main(string[] args) {
    bool isPlaying = false;
    auto lastTime = MonoTime.currTime;       // last execution time
    auto interval = dur!"msecs"(100);
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
    scope(exit) endwin();
    cbreak();
    noecho();
    keypad(stdscr, true);

    timeout(100);

    // Create a large pad for instructions
    instrPad = newpad(10000, 200);

    cortex_m_vm vm;
    vm.load_program(objdump_file_name);

    auto file_mem = File("mem.txt", "w");
    for (size_t i = memory.flash_origin; i < memory.flash_origin + memory.flash_length; i += 4) {
        uint val = vm.mem.read_word(i);
        if (val != 0) {
            file_mem.writeln("PC = 0x", format("[%08X]: %08X", i, val));
        }
    }
    file_mem.close();

    auto file = File("pc.txt", "w");

    func[] f_s;
    if (objdump_file_name == "../test/cortex_m_asm.txt") {
        foreach (name; bare_metal_func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else if (objdump_file_name == "../test/zephyr_led_asm.txt") {
        foreach (name; zephyr_func_names) {
            func f = get_function(objdump_file_name, name);
            f_s ~= f;
        }
    } else {
        foreach (name; freertos_func_names) {
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
                file.writeln("PC = 0x", format("%08X", vm.cpu.pc));
                file.flush();
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
        }

        auto now = MonoTime.currTime;
        if (isPlaying) {
            auto delta = now - lastTime; // delta is already a Duration
            if (delta >= interval) {
                file.writeln("PC = 0x", format("%08X", vm.cpu.pc));
                file.flush();
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

