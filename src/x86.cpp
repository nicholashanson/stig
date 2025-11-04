#include <x86.hpp>

namespace stig {

	// ===============
    //  Parse Address
    // ===============

	std::expected<x86_instruction_parse_result,std::string> parse_address( x86_instruction_parse_result p_result ) {
    	std::size_t colon_pos = p_result.buffer.find( ':' );
    	if ( colon_pos == std::string_view::npos ) {
        	return std::unexpected( "Missing ':' after Address" );
    	}
		std::string_view addr_str = p_result.buffer.substr( 0, colon_pos );
    	uint64_t address;
    	auto [ ptr, ec ] = std::from_chars( addr_str.data(), addr_str.data() + addr_str.size(), address, 16 );
    	if ( ec != std::errc() ) {
        	return std::unexpected( "Invalid Address" );
    	}
		p_result.instruction.address = address;
		p_result.pos = colon_pos + 1;
    	return p_result;
    }

    // =======================
    //  Extract Machine Bytes
    // =======================

    std::expected<x86_instruction_parse_result,std::string> extract_machine_bytes( x86_instruction_parse_result p_result ) {
    	std::istringstream iss( std::string( p_result.buffer ) );
	    std::string token;
	    iss.seekg( p_result.pos, std::ios::beg );
	    std::vector<uint8_t> bytes;
	    while ( iss >> token ) {
	        if ( token.size() > 2 ) { 
	        	break;
	        }
	        bool is_hex = token.find_first_not_of( "0123456789abcdefABCDEF" ) == std::string::npos;
	        if ( !is_hex ) {
	        	if ( token == "cs" ) {
	        		p_result.pos = iss.tellg();
	        		break;
	        	} 
	        	break;
	        }
	        p_result.pos = iss.tellg();
	        uint8_t value = static_cast<uint8_t>( std::stoul( token, nullptr, 16 ) );
	        bytes.push_back( value );
	    }
	    p_result.instruction.machine_bytes = std::move( bytes );
	    return p_result;
    } 

    // ================
    //  Parse Mnemonic
    // ================

    std::expected<x86_instruction_parse_result,std::string> parse_mnemonic( x86_instruction_parse_result p_result ) {
    	if ( std::all_of( p_result.instruction.machine_bytes.begin(), p_result.instruction.machine_bytes.end(), 
    		 [&]( auto& byte){ return byte == 0x00; } ) ) {
    		p_result.instruction.mnemonic = x86_mnemonic::padding;
    		return p_result;
    	}
    	std::istringstream iss( std::string( p_result.buffer ) );
	    std::string token;
	    iss.seekg( p_result.pos, std::ios::beg );
	    iss >> token;
	    auto it = mnemonic_map.find( token );
		if ( it != mnemonic_map.end() ) {
		    p_result.instruction.mnemonic = it->second;
		} else {
		    return std::unexpected( "Unknown Mnemonic: " + token );
		}
	    p_result.pos = iss.tellg();
	    ++p_result.pos; 
	    return p_result;
    }

    // ==============
    //  Get Register
    // ==============

    std::optional<x86_register> get_register( const std::string& token ) {
    	if ( token == "%eax" ) return x86_register::eax;
    	if ( token == "%edx" ) return x86_register::edx;
    	if ( token == "%edi" ) return x86_register::edi;
    	if ( token == "%esi" ) return x86_register::esi;
    	if ( token == "%rax" ) return x86_register::rax;
    	if ( token == "%rbp" ) return x86_register::rbp;
    	if ( token == "%rdi" ) return x86_register::rdi;
    	if ( token == "%rip" ) return x86_register::rip;
    	if ( token == "%rsp" ) return x86_register::rsp;
    	if ( token == "%rsi" ) return x86_register::rsi;
    	return std::nullopt;
    }

    // ===============
    //  Get Immediate
    // ===============

    std::optional<x86_immediate> get_immediate( const std::string& token ) {
    	if ( !token.empty() && token[ 0 ] == '$' ) {
	        try {
	            int64_t value = std::stoll( token.substr( 1 ), nullptr, 0 );
	            return x86_immediate{ value };
	        } catch ( const std::exception& ) {
	            return std::nullopt;
	        }
	    }
	    return std::nullopt;
    }

    // ================
    //  Contains Comma
    // ================

    bool contains_comma( const std::string& input ) {
    	return input.find( ',' ) != std::string::npos;
	}

	// =============
    //  Split Token
    // =============

	std::vector<std::string> split_token( const std::string& token ) {
	    std::vector<std::string> result;
	    std::stringstream ss( token );
	    std::string part;
	    while ( std::getline( ss, part, ',' ) ) {
	        result.push_back( part );
	    }
	    return result;
	}

	// ============
    //  Get Memory
    // ============

    std::expected<x86_memory,std::string> get_memory( const std::string& token ) {
    	x86_memory result{};
    	auto open_paren = token.find( '(' );
        auto close_paren = token.find( ')' );

        if ( open_paren == std::string::npos || close_paren == std::string::npos ) {
        	return std::unexpected( "No Pair of Paranetheses found" );
        }
        std::string disp_str = token.substr( 0, open_paren );          
        std::string reg_str  = token.substr( open_paren + 1, close_paren - open_paren - 1 );
	    if ( !disp_str.empty() ) {
	        auto disp_result = parse_displacement( disp_str );
	        if ( !disp_result ) {
	        	return std::unexpected( disp_result.error() );
	        }
	        result.displacement = disp_result.value();
	    }
        auto register_result = get_register( reg_str );
        if ( !register_result ) {
        	return std::unexpected( "Unrecognized Register: " + reg_str ); 
        }
        result.base = register_result.value();
        return result;
    }

   	// ====================
    //  Parse Displacement
    // ====================

    std::expected<int64_t,std::string> parse_displacement( const std::string& token ) {
    	try {
	        int64_t displacement = std::stoll( token, nullptr, 0 );
	        return displacement;
	    } catch ( const std::exception& e ) {
	        return std::unexpected( std::string( "Invalid displacement: " ) + e.what() );
	    }
    }

    // ================
    //  Parse Operands
    // ================

    std::expected<x86_instruction_parse_result,std::string> parse_operands( x86_instruction_parse_result p_result ) {
    	if ( p_result.instruction.mnemonic == x86_mnemonic::endbr64 ||
    		 p_result.instruction.mnemonic == x86_mnemonic::ret ||
    		 p_result.instruction.mnemonic == x86_mnemonic::call ||
    		 p_result.instruction.mnemonic == x86_mnemonic::je ||
    		 p_result.instruction.mnemonic == x86_mnemonic::jmp ||
    		 p_result.instruction.mnemonic == x86_mnemonic::padding ) {
    		return p_result;
    	}
    	std::string token;
    	std::istringstream iss( std::string( p_result.buffer ) );
    	iss.seekg( p_result.pos, std::ios::beg );
    	while ( iss >> token ) {
    		auto operands = split_token( token );
    		bool valid_token = true;
    		p_result.instruction.operands.emplace();
    		for ( auto& operand : operands ) {
		        auto register_result = get_register( operand );
		        if ( register_result ) {
		        	p_result.instruction.operands->push_back( register_result.value() );
		        	continue;
		        }
		        auto immediate_result = get_immediate( operand );
		        if ( immediate_result ) {
		        	p_result.instruction.operands->push_back( immediate_result.value() );
		        	continue;
		        }
		        auto memory_result = get_memory( operand );
		        if ( memory_result ) {
		        	p_result.instruction.operands->push_back( memory_result.value() );
		        	continue;
		        }
		        valid_token = false;
		    }
		    break;
	    }
    	return p_result;
    }

    // ============
    //  Parse Call
    // ============

    std::expected<x86_instruction_parse_result,std::string> parse_call( x86_instruction_parse_result p_result ) {
    	if ( p_result.instruction.mnemonic != x86_mnemonic::call && 
    		 p_result.instruction.mnemonic != x86_mnemonic::je &&
    		 p_result.instruction.mnemonic != x86_mnemonic::jmp ) {
    		return p_result;
    	}
    	std::string token;
    	std::istringstream iss( std::string( p_result.buffer ) );
    	iss.seekg( p_result.pos, std::ios::beg );
    	iss >> token;
    	try {
    		if ( !token.empty() && token[ 0 ] == '*' ) {
            	std::string reg_name = token.substr( 1 ); 
            	auto reg_opt = get_register( reg_name ); 
            	if ( reg_opt ) {
            		p_result.instruction.operands.emplace();
            		p_result.instruction.operands->push_back( reg_opt.value() );
            		return p_result;
            	}
            	auto memory_result = get_memory( reg_name );
            	if ( memory_result ) {
            		p_result.instruction.operands.emplace();
            		p_result.instruction.operands->push_back( memory_result.value() );
            		return p_result;
            	}
            	if ( !reg_opt ) {
            		return std::unexpected( "Unrecognized Register: " + reg_name );
            	}
            	if ( !memory_result ) {
            		return std::unexpected( "Failed to parse as memory: " + reg_name );
            	}
            } else {
		        uint64_t address = std::stoll( token, nullptr, 16 ); 
		        p_result.instruction.operands.emplace();
		        p_result.instruction.operands->push_back( x86_address{ address } );
		    }
	    } catch ( const std::exception& e ) {
	        return std::unexpected( std::string( "Invalid Address: " ) + e.what() );
	    }
	    return p_result;
    }

    // =======================
    //  Parse x86 Instruction
    // =======================

	std::expected<x86_instruction_parse_result,std::string> parse_x86_instruction( std::string instruction ) {
		return parse_address( { x86_instruction{}, instruction } )
			.and_then( extract_machine_bytes )
			.and_then( parse_mnemonic )
			.and_then( parse_operands )
			.and_then( parse_call );
	}


	// ================
    //  Parse Function
    // ================

    std::expected<std::string,std::string> parse_function_name( const std::string& token ) {
    	auto open_angle = token.find( '<' );
        auto close_angle = token.find( '>' );

        if ( open_angle == std::string::npos || close_angle == std::string::npos ) {
        	return std::unexpected( "No Angle Brackets found" );
        }
        std::string function_name = token.substr( open_angle + 1, close_angle - open_angle - 1 );
        return function_name;
    }

    // ======
    //  Trim
    // ======

    std::string trim( const std::string& s ) {
	    auto start = std::find_if_not( s.begin(), s.end(), ::isspace );
	    auto end   = std::find_if_not( s.rbegin(), s.rend(), ::isspace ).base();
	    if ( start >= end ) {
	        return "";
	    }
	    return std::string( start, end );
	}

    // =============
    //  Split Lines
    // =============

    std::vector<std::string> split_lines( const std::string& text ) {
	    std::vector<std::string> lines;
	    std::istringstream stream( text );
	    std::string line;
	    while ( std::getline( stream, line ) ) {
	        if ( !line.empty() ) {  
	     		std::cout << trim( line ) << std::endl;
	            lines.push_back( trim( line ) );
	        }
	    }
	    return lines;
	}

	// ================
    //  Parse Function
    // ================

	std::expected<function,std::string> parse_function( const std::string& token ) {
		function func;
		auto lines = split_lines( token );
		if ( lines.empty() ) {
			return std::unexpected( "Function Body is empty" );
		}
		auto name_result = parse_function_name( lines[ 0 ] );
		if ( !name_result ) {
			return std::unexpected( name_result.error() );
		}
		func.name = name_result.value();
		for ( std::size_t i = 1; i < lines.size(); ++i ) {
			auto parse_result = parse_x86_instruction( lines[ i ] );
			if ( !parse_result ) {
				return std::unexpected( parse_result.error() );
			}
			auto& parsed_instruction = parse_result.value();
			func.instructions.push_back( parsed_instruction.instruction );
		}
 		return func;
	}

	// ============================
    //  Parse x86 Instruction : <<
    // ============================

    /*

	std::ostream& operator<<( std::ostream& os, x86_instruction instruction ) {
		const int label_width = 26;
        os << std::dec << std::setfill( ' ' );

        auto print_field = [&]( const std::string& label, auto value ) {
            os << std::left << std::setw( label_width ) << label << value << "\n";
        };

        os << "======X86 INSTRUCTION BEGIN======\n";
        print_field("Mnemonic:", mnemonic_names.at( instruction::mnemonic ) );
        os << "======X86 INSTRUCTION END=====\n\n";
        return os;
	}

	*/

}