#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/node.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/screen/string.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>

#include <string>
#include <sstream>
#include <iomanip>

#include <x86.hpp>

using namespace ftxui;

struct color_scheme {
    ftxui::Color mnemonic;    
    ftxui::Color reg;          
    ftxui::Color immediate;    
    ftxui::Color address;      
    ftxui::Color memory;
    ftxui::Color highlight;     
};

color_scheme monokai = {
    ftxui::Color::BlueLight,   // mnemonic
    ftxui::Color::Yellow,      // registers
    ftxui::Color::Cyan,        // immediate values
    ftxui::Color::Magenta,     // addresses
    ftxui::Color::Green,       // memory
    ftxui::Color::GrayLight 
};

std::string hex64( int64_t v ) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::setw( 16 ) << std::setfill( '0' ) << ( uint64_t )v;
    return ss.str();
}

std::string hex64_zero_width( int64_t v ) {
    std::stringstream ss;
    ss << "0x" << std::hex;
    ss << (uint64_t)v;
    return ss.str();
}

std::string hex64_zero_width_addr( int64_t v ) {
    std::stringstream ss;
    ss << std::hex << (uint64_t)v;
    return ss.str();
}

ftxui::Element instr_to_element( const stig::x86_instruction& instr, const color_scheme& cs ) {
    using namespace ftxui;

    std::vector<Element> operands;

    if ( instr.operands.has_value() ) {
        for ( auto& op : instr.operands.value() ) {
            operands.push_back( std::visit([&]( auto&& operand ) -> Element {
                using T = std::decay_t<decltype( operand )>;
                if constexpr (std::is_same_v<T, stig::x86_register>) {
                    return text(stig::register_names.at(operand)) | color(cs.reg);
                }
                if constexpr (std::is_same_v<T, stig::x86_immediate>) {
                    return text(hex64_zero_width(operand.value)) | color(cs.immediate);
                }
                if constexpr (std::is_same_v<T, stig::x86_address>) {
                    return text(hex64_zero_width(operand.addr)) | color(cs.address);
                }
                if constexpr (std::is_same_v<T, stig::x86_memory>) {
                    return text(stig::memory_to_str(operand)) | color(cs.memory);
                }
                return text("unhandled");
            }, op));
        }
    }

    std::vector<Element> operand_line;
    for (size_t i = 0; i < operands.size(); ++i) {
        operand_line.push_back(operands[i]);
        if (i != operands.size() - 1) {
            operand_line.push_back(text(", ")); // add comma between operands
        }
    }

    // Build the instruction line
    Element line = hbox({
        text(hex64_zero_width_addr(instr.address)) | color(cs.address) | bold,
        text(" "),
        text(stig::mnemonic_names.at(instr.mnemonic)) | color(cs.mnemonic) | bold,
        text(" "),
        hbox(operand_line)
    });

    return line;
}

Element cpu_view( const stig::x86_cpu& cpu ) {
    return 
        window(
            text("CPU STATE"),
            vbox({
                text( " RAX: " + hex64(cpu.rax)),
                text( " RBP: " + hex64(cpu.rbp)),
                text( " RDI: " + hex64(cpu.rdi)),
                text( " RSI: " + hex64(cpu.rsi)),
                text( " RDX: " + hex64(cpu.rdx)),
                text( " RSP: " + hex64(cpu.rsp)),
                text( " R8 : " + hex64(cpu.r8)),
                text( " R9 : " + hex64(cpu.r9)),
                text( " R10: " + hex64(cpu.r10)),
                text( " R11: " + hex64(cpu.r11)),
                text( " R12: " + hex64(cpu.r12)),
                text( " R13: " + hex64(cpu.r13)),
                text( " R14: " + hex64(cpu.r14)),
                text( " R15: " + hex64(cpu.r15)),

                separator(),
                text(" RIP: " + hex64(cpu.rip)),
                separator(),

                text(" Flags: "
                     "ZF=" + std::to_string(cpu.zero_flag) +
                     " CF=" + std::to_string(cpu.carry_flag) +
                     " SF=" + std::to_string(cpu.sign_flag) +
                     " OF=" + std::to_string(cpu.overflow_flag)
                ),
            })
        );
}

Element instr_view( const std::vector<stig::function>& funcs, const color_scheme& cs,
                    const stig::x86_cpu& cpu ) {
    std::vector<Element> lines;
    for ( auto& func : funcs ) { 
        if ( func.name != "_start" ) {
            lines.push_back( separator() );
        }
        lines.push_back( text( func.name ) );
        lines.push_back( separator() );
        for ( const auto& instr : func.instructions ) {
            Element line = instr_to_element(instr, cs);
            if ( instr.address == cpu.rip ) {
                 line = line | bgcolor( cs.highlight );
            }
            lines.push_back(line);
        }
    }
    return window( text( "Instructions" ), vbox( std::move( lines ) ) );
}

Element main_view( stig::x86_vm& vm, const color_scheme& cs ) {
    auto cpu_panel = cpu_view( vm.cpu );
    Element instr_panel;
    if ( !vm.current_program._init.empty() ) {
        instr_panel = instr_view( vm.current_program._init, cs, vm.cpu );
    } else {
        instr_panel = window( text( "Instructions" ), text( "<empty>" ) );
    }
    return hbox({
        cpu_panel | flex,
        instr_panel | flex,
    });
}

int main( int argc, char** argv ) {
    stig::x86_vm vm{};

    std::string obj_file;
    for ( int i = 1; i < argc; ++i ) {
        std::string arg = argv[ i ];
        auto eq = arg.find( '=' );
        if ( eq != std::string::npos ) {
            std::string key = arg.substr( 0, eq );
            std::string val = arg.substr( eq + 1 );
            if ( key == "obj" ) {
                obj_file = val;
            }
        }
    }
    if ( !obj_file.empty() ) {
        std::cout << "Loading object file: " << obj_file << "\n";
        auto load_res = vm.load_program( obj_file );
        if ( !load_res ) {
            std::cout << "Failed to load file: " << load_res.error() << std::endl;
        }
    }

    auto screen = ScreenInteractive::Fullscreen();

    auto app = CatchEvent(Renderer([&] { 
            return main_view(vm, monokai); 
        }),
        [&](Event e) {
            if (e == Event::ArrowDown) {
                // Execute the next instruction when down arrow is pressed
                auto exec_res = vm.execute_next_instr();
                if ( !exec_res ) {
                    std::cout << exec_res.error() << std::endl;
                }
                return true; // event handled
            }
            return false; // event not handled
        });

    screen.Loop( app );

    return 0;
}
