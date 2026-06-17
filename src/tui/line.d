import deimos.ncurses;
import std.string : toStringz;

// --------------------------------------------------------------------------------------
// ==============
//  PRINT STRING
// ==============

void print_string(WINDOW* win, const int y, const int x, string s, int color) {
    wattron(win, COLOR_PAIR(color)); 
    mvwprintw(win, y, x, toStringz(s));
    wattroff(win, COLOR_PAIR(color));
}
// --------------------------------------------------------------------------------------