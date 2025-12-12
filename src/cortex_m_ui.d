import deimos.ncurses;
import cortex_m;
import std.format;
import std.string : toStringz;
import std.variant : VariantN;
import std.stdio;
import std.conv;
import std.algorithm;
import core.runtime : Runtime;

// Global pad and scroll offset:
WINDOW* instrPad;
int padPos = 0;

void draw_screen(cortex_m_vm vm, func[] functions) {
    clear(); // clear screen

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
    uint ptr = vm.cpu.sp;
    while (ptr < vm.mem.stack_base) {
        uint val = vm.mem.read_word(ptr);
        mvwprintw(stdscr, regY++, regX, toStringz(format("%08x: %08x", ptr, val)));
        ptr += 4;
    }

    // ----------------------------
    // Right pane: instructions ON PAD
    // ----------------------------
    werase(instrPad);  // clear pad for redraw

    int instrPadRow = 0;
    int instrPadCol = 0;

    foreach (f; functions) {
        mvwprintw(instrPad, instrPadRow++, instrPadCol,
                      toStringz(format("%s", f.name)));
        foreach (ins; f.instrs) {
            string s;

            if (ins._addr == vm.cpu.pc)
                wattron(instrPad, A_REVERSE);

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
                    if (i32.op == opcode.bl_32) {
                        uint target = ins._addr + i32.offset + 4;
                        s ~= format(" %x", target);
                    }
                }
                catch (Exception) {
                    s = "Unknown instruction type";
                }
            }

            mvwprintw(instrPad, instrPadRow++, instrPadCol,
                      toStringz(format("%x: %s %s", ins._addr, ins._instr_bytes, s)));

            if (ins._addr == vm.cpu.pc)
                wattroff(instrPad, A_REVERSE);
        }
        instrPadRow++;
    }

    refresh();
    // Draw pad into right side of screen
    int instrScreenX = 50;   // <-- visible position
    prefresh(instrPad,
             padPos, 0,           // first line of pad to show
             0, COLS / 2 - 1,     // location on real screen
             LINES - 1, COLS - 1  // bottom-right of real screen
    );

    //mvwprintw(stdscr, 0, 0, toStringz(format("%d: %d", LINES, COLS)));
}

void main(string[] args) {
    uint entryPoint = 0; 

    if (args.length > 1) {
        try {
            entryPoint = to!uint(args[1], 16);
        } catch (ConvException e) {
            writeln("Invalid entry point: ", args[1]);
            return;
        }
    }

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, true);

    // Create a large pad for instructions
    instrPad = newpad(10000, 200);

    cortex_m_vm vm;
    vm.load_program("../test/cortex_m_asm.txt");
    string[] func_names = [
        "SystemInit",
        "Reset_Handler",
        "CopyDataInit",
        "LoopCopyDataInit",
        "FillZerobss",
        "LoopFillZerobss",
        "__libc_init_array",
        "_init",
        "register_fini",
        "atexit",
        "__register_exitproc",
        "frame_dummy",
        "register_tm_clones",
        "main",
        "HAL_Init",
        "HAL_NVIC_SetPriorityGrouping",
        "__NVIC_SetPriorityGrouping"
    ];

    func[] f_s;
    foreach (name; func_names) {
        func f = get_function("../test/cortex_m_asm.txt", name);
        f_s ~= f;
    }

    if (entryPoint != 0) {
        vm.run_to(entryPoint);
    }

    draw_screen(vm, f_s);

    int ch;
    while ((ch = getch()) != 'q') {
        if (ch == KEY_DOWN) {
            vm.execute_next_instr();
        }
        if (ch == 'z') { // scroll down
            padPos = min(padPos + 1, vm.current_program.length + (f_s.length * 2) - LINES);
        }
        if (ch == 'x') { // scroll up
            padPos = max(padPos - 1, 0);
        }

        draw_screen(vm, f_s);
    }

    endwin();
}

