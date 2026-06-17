import deimos.ncurses;
import control_loop;
import thumb_2_convert_instr_to_string;
import std.algorithm;
import std.string : toStringz;
import reg_view;

struct instr_panel {
   WINDOW*       instr_pad;    
   WINDOW* instr_pad_frame;
   WINDOW*         scb_pad;
   int               start;
   int                 end;
   int visible_lines  = 39;
   int curr_pc_row =    -1;
   uint curr_pc;
   int last_pc_screen_row;
   int last_pc_row;
   int col;
   int screen_row;

   int get_curr_pc_row(const ref row_view[] rows) {
      int curr_pc_row = 0;
      foreach (r; rows) {
         if (r.addr == curr_pc) {
            return curr_pc_row;
         } else {
            curr_pc_row++;
         }
      }
      assert(0);
   }

   void update_instr_range(ref runtime_ctrl ctrl, const ref row_view[] rows) {
      if (ctrl.pc_moved) {
         int old_start = start;
         bool pad_is_focused = (curr_pc_row >= start) && (curr_pc_row < end);

         if (!pad_is_focused) {
            start = max(0, curr_pc_row - 5);
            end   = min(start + visible_lines, rows.length);
         }

         int bottom_margin = 5;
         int distance_to_bottom = end - curr_pc_row;
         if (distance_to_bottom < bottom_margin) {
            int delta = bottom_margin - distance_to_bottom;
            end   = min(end + delta, rows.length);
            start = end - visible_lines;
         }

         if (old_start != start) { 
            werase(instr_pad);
            ctrl.instr_view_changed = true;
         }
      }
   }

   void clear_instrs(ref runtime_ctrl ctrl) {
      if (ctrl.instr_view_changed) {
            werase(instr_pad);
      }
   }

   void draw_instrs(ref runtime_ctrl ctrl, const ref row_view[] rows) {
      static uint last_pc_row;
      static uint pc_screen_row;
      static uint last_pc_screen_row;
      if (ctrl.instr_view_changed || ctrl.first_draw) {
           for (int j = start; j < end; ++j) {
               auto r = rows[j];
               if (r.type == row_view.kind.func_name) 
                   mvwprintw(instr_pad, screen_row++, col, toStringz(r.s));
               if (r.type == row_view.kind.instr) {
                   if (r.addr == curr_pc) {
                       curr_pc_row = j;
                       pc_screen_row = screen_row;
                       wattron(instr_pad, A_REVERSE);
                       mvwprintw(instr_pad, pc_screen_row, col, toStringz(rows[curr_pc_row].s));
                       wattroff(instr_pad, A_REVERSE);
                       screen_row++;
                   } else {
                       print_colored_reg_line(instr_pad, screen_row++, col, r.s);
                   }
               }
               if (r.type == row_view.kind.blank_line) 
                   screen_row++;
           }
       } else {
           if (ctrl.pc_moved) {
               for (int j = start; j < end; ++j) {
                   auto r = rows[j];
                   if (r.type == row_view.kind.instr) {
                       if (r.addr == curr_pc) {
                           curr_pc_row = j;
                           pc_screen_row = screen_row;
                       }
                   }
                   screen_row++;
               }
               wattron(instr_pad, A_REVERSE);
               mvwprintw(instr_pad, pc_screen_row, col, toStringz(rows[curr_pc_row].s));
               wattroff(instr_pad, A_REVERSE);
               print_colored_reg_line(instr_pad, last_pc_screen_row++, col, rows[last_pc_row].s);
           }
       }
       last_pc_screen_row = pc_screen_row;
       last_pc_row = curr_pc_row;
   }

   void draw(ref runtime_ctrl ctrl, const uint pc, const ref row_view[] rows) {
      screen_row = 0;
      col        = 1;
      curr_pc = pc;
      curr_pc_row = get_curr_pc_row(rows);
      update_instr_range(ctrl, rows);
      clear_instrs(ctrl);
      draw_instrs(ctrl, rows);
   }

   void refresh() {
      wnoutrefresh(instr_pad_frame);
      prefresh(instr_pad,
         0,                                         0,          
         frame_y + 1,                     frame_x + 1,     
         frame_y + frame_h - 2, frame_x + frame_w - 2  
      );
   }
}