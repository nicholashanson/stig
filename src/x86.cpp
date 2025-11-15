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
	        if ( token.size() > 2 && token != "lock" ) { 
	        	break;
	        }
	        bool is_hex = token.find_first_not_of( "0123456789abcdefABCDEF" ) == std::string::npos;
	        if ( !is_hex ) {
	        	if ( token == "cs" || token == "lock" ) {
	        		std::cout << "here" << std::endl;
	        		p_result.pos = iss.tellg();
	        		std::cout << "pos: " << p_result.pos << std::endl;
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
		    std::cout << mnemonic_names.at( p_result.instruction.mnemonic ) << std::endl;
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
		std::string token_copy( token );
		bool inside_paren = false;
		for ( auto& c : token_copy ) {
			if ( c == '(' ) {
				inside_paren = true;
			}
			if ( c == ')' ) {
				inside_paren = false;
			}
			if ( c == ',' && inside_paren ) {
				c = '#';
			}
		}
	    std::vector<std::string> result;
	    std::stringstream ss( token_copy );
	    std::string part;
	    while ( std::getline( ss, part, ',' ) ) {
	    	for ( auto& c : part ) {
	    		if ( c == '#' ) {
	    			c = ',';
	    		}
	    	}
	        result.push_back( part );
	    }
	    return result;
	}

	// ============
    //  Get Memory
    // ============

    std::expected<x86_memory,std::string> get_memory( const std::string& token ) {
    	std::cout << "token1: " << token << std::endl;
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
	    auto first_comma = reg_str.find( ',' );
	    auto second_comma = std::string::npos; 
	    if ( first_comma != std::string::npos ) {
	    	second_comma = reg_str.find( ',', first_comma + 1 );
	    }  
	    if ( second_comma != std::string::npos ) {
	    	auto base_reg_result = get_register( reg_str.substr( 0, first_comma ) );
	    	if ( !base_reg_result ) {
	    		return std::unexpected( "Unrecognized Base Register: " + reg_str );
	    	}
	    	result.base = base_reg_result.value();
	    	auto index_reg_result = get_register( reg_str.substr( first_comma + 1, second_comma - first_comma - 1 ) );
	    	if ( !index_reg_result ) {
	    		return std::unexpected( "Unrecognized Index Register: " + reg_str ); 
	    	}
	    	result.index = index_reg_result.value();
	    	auto scale_result = parse_displacement( reg_str.substr( second_comma + 1 ) );
	    	if ( !scale_result ) {
	    		return std::unexpected( "Unrecognized Scale:" + reg_str );
	    	}
	    	result.scale = scale_result.value();
	    	return result;
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

	// ====================
    //  Convert to Program
    // ====================

    std::expected<program,std::string> convert_to_program( function& func ) {
    	program result;
    	for ( auto& instr : func.instructions ) {
    		result.instrs.insert( std::pair<uint64_t,x86_instruction>{ instr.address, instr } );
    	}
    	return result;
    }

	// =============
    //  Execute Xor
    // =============

    std::expected<void,std::string> execute_xor( const x86_instruction& xor_instr, x86_cpu& cpu ) {
    	if ( !xor_instr.operands.has_value() ) {
    		return std::unexpected( "Xor Instruction does not contain any Operands" );
    	}
    	if ( xor_instr.operands->size() == 1 ) {
    		return std::unexpected( "Xor Instruction contains only one Operand" );
    	}
    	if ( xor_instr.operands->size() != 2  ) {
    		return std::unexpected( "Xor Instruction contains more than two Operands" );
    	}
    	auto& operands = xor_instr.operands.value();
    	bool undhandled = false;
    	std::optional<std::string> error;
    	auto lhs = std::visit( [ &cpu, &undhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
        		if ( auto res = cpu.get( op ) ) {
        			return res.value();
        		} else {
        			error = res.error();
        		}        
    		}
    		undhandled = true;
    		return uint64_t{0};
    	}, operands[ 0 ] );
    	if ( undhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Left-Hand Operand not handled" );
    		}
    	}
		auto rhs = std::visit( [ &cpu, &undhandled, &error ]( auto&& op ) {
			using T = std::decay_t<decltype( op )>;
			if constexpr ( std::is_same_v<T,x86_register> ) {
        		if ( auto res = cpu.get( op ) ) {
        			return res.value();
        		} else {
        			error = res.error();
        		}          
    		}
    		undhandled = true;
    		return uint64_t{0};
		}, operands[ 1 ] );
		if ( undhandled ) {
			if ( error.has_value() ) {
				return std::unexpected( error.value() );
			} else {
				return std::unexpected( "Right-Hand Operand not handled" );
			}
		}  
		auto val = lhs ^ rhs;
		std::visit( [ &cpu, val, &undhandled, &error ]( auto&& op ) {
			using T = std::decay_t<decltype( op )>;
			if constexpr ( std::is_same_v<T,x86_register> ) {
        		auto res = cpu.set( op, val );   
        		if ( !res ) {
        			error = res.error();
        		} else {
        			return;
        		}
    		}
    		undhandled = true;
    		return;
		}, operands[ 0 ] );
		if ( undhandled ) {
			if ( error.has_value() ) {
				return std::unexpected( error.value() );
			} else {
				return std::unexpected( "Unhandled Operand" );
			}
		}
		return {};
    }

    // =============
    //  Execute Mov
    // =============

    std::expected<void,std::string> execute_mov( const x86_instruction& mov_instr, x86_cpu& cpu ) {
    	if ( !mov_instr.operands ) {
    		return std::unexpected( "Mov Instruction does not contain any Operands" );
    	}
    	if ( mov_instr.operands->size() == 1 ) {
    		return std::unexpected( "Mov Instruction contains only one Operand" ); 
    	}
    	if ( mov_instr.operands->size() != 2 ) {
    		return std::unexpected( "Mov Instruction contains more than two Operands" );
    	}
    	auto& operands = mov_instr.operands.value();
    	bool unhandled = false;
    	std::optional<std::string> error;
    	auto val = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
        		if ( auto res = cpu.get( op ) ) {
        			return res.value();	
        		} else {
        			error = res.error();
        		}
    		}
    		unhandled = true;
    		return uint64_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Unhandled Operand" );
    		}
    	}
    	std::visit( [ &cpu, val, &unhandled, &error ]( auto&& op ) {
			using T = std::decay_t<decltype( op )>;
			if constexpr ( std::is_same_v<T,x86_register> ) {
        		auto res = cpu.set( op, val );
        		if ( !res ) {
        			error = res.error();
        		} else {
        			return;
        		}         
    		}
    		unhandled = true;
    		return;
		}, operands[ 1 ] );
		if ( unhandled ) {
			if ( error.has_value() ) {
				return std::unexpected( error.value() );
			} else {
				return std::unexpected( "Unhandled Operand" );
			}
		}
		return{};
    }

    // ==============
    //  Execute Movb
    // ==============

    std::expected<void,std::string> execute_movb( const x86_instruction& movb_instr, x86_cpu& cpu, std::unordered_map<uint64_t,uint8_t>& ram ) {
    	if ( !movb_instr.operands.has_value() ) {
    		return std::unexpected( "Movb Instruction has no Operands" );
    	}
    	auto& operands = movb_instr.operands.value();
    	std::optional<std::string> error;
    	bool unhandled = false;
    	auto lhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.get( op ) ) {
    				return static_cast<uint8_t>( res.value() );
    			} else {
    				error = res.error();
    			}
    		}
    		if constexpr ( std::is_same_v<T,x86_immediate> ) {
    			return static_cast<uint8_t>( op.value );
    		}
    		unhandled = true;
    		return uint8_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Left-Hand Operand unhandled" );
    		}
    	}
    	auto rhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.get( op ) ) {
    				return res.value();
    			} else {
    				error = res.error();
    			}
    		}
    		if constexpr ( std::is_same_v<T,x86_memory> ) {
    			uint64_t addr{};
    			if ( !op.base.has_value() ) {
    				error = "Memory has no Base Register";
    				unhandled = true;
    				return uint64_t{0};
    			}
    			if ( !op.displacement.has_value() ) {
    				error = "Memory has no Displacement";
    				unhandled = true;
    				return uint64_t{0};
    			}
    			if ( auto res = cpu.get( op.base.value() ) ) {
    				addr = res.value();
    				addr += op.displacement.value();
    				return addr;
    			} else {
    				error = res.error();
    			}
    		}
    		unhandled = true;
    		return uint64_t{0};
    	}, operands[ 1 ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Right-Hand Operand unhandled" );
    		}
    	}
    	ram.insert( std::pair<uint64_t,uint8_t>( rhs, lhs ) );
    	return {};
    }

    // =============
    //  Execute Cmp
    // =============

    std::expected<void,std::string> execute_cmp( const x86_instruction& cmp_instr, x86_cpu& cpu ) {
    	if ( !cmp_instr.operands ) {
    		return std::unexpected( "Cmp Instruction does not contain any Operands" );
    	}
    	if ( cmp_instr.operands->size() == 1 ) {
    		return std::unexpected( "Cmp Instruction contains only one Operand" );
    	}
    	if ( cmp_instr.operands->size() != 2 ) {
    		return std::unexpected( "Cmp Instruction contains more than two Operands" );
    	} 
    	auto& operands = cmp_instr.operands.value();
    	bool unhandled = false;
    	std::optional<std::string> error;
    	auto lhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
        		if ( auto res = cpu.get( op ) ) {
        			return res.value();
        		} else {
        			error = res.error();
        		}        
    		}
    		unhandled = true;
    		return uint64_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Left-Hand Operand is not handled" );
    		}
    	}
		auto rhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
			using T = std::decay_t<decltype( op )>;
			if constexpr ( std::is_same_v<T,x86_register> ) {
        		if ( auto res = cpu.get( op ) ) {
        			return res.value();
        		} else {
        			error = res.error();
        		}
    		}
    		unhandled = true;
    		return uint64_t{0};
		}, operands[ 1 ] );
		if ( unhandled ) {
			if ( error.has_value() ) {
				return std::unexpected( error.value() );
			} else {
				return std::unexpected( "Right-Hand Operand is not handled" );
			}
		}
		int64_t signed_diff = static_cast<int64_t>( lhs ) - static_cast<int64_t>( rhs );
		uint64_t unsigned_diff = lhs - rhs;
		cpu.zero_flag = ( signed_diff == 0 );
    	cpu.sign_flag = ( signed_diff  < 0 );
    	cpu.carry_flag = ( lhs < rhs ); 
    	cpu.overflow_flag = ( ( lhs ^ rhs ) & ( lhs ^ signed_diff ) ) >> 63;
    	return {};
    }

    // ==============
    //  Execute Push
    // ==============

    std::expected<void,std::string> execute_push( const x86_instruction& push_instr, x86_cpu& cpu ) {
    	if ( !push_instr.operands ) {
    		return std::unexpected( "Push Instruction does not contain any Operands" );
    	}
    	if ( !push_instr.operands->size() == 1 ) {
    		return std::unexpected( "Push Instruction contains more than one Operand" );
    	}
    	bool unhandled = false;
    	auto& operands = push_instr.operands.value();
    	int reg_width{};
    	std::optional<std::string> error;
    	auto val = std::visit( [ &cpu, &reg_width, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			auto res = get_register_width( op );
    			if ( !res ) {
    				unhandled = true;
    				error = res.error();
    			} else {
    				reg_width = res.value();
        			if ( auto op_result = cpu.get( op ) ) {
        				return op_result.value();
        			} else {
        				error = op_result.error();
        			}
        		}        
    		}
    		unhandled = true;
    		return uint64_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Unhandled Operand" );
    		}
    	}
    	int size = reg_width / 8;
    	for ( int i = 0; i < size; ++i ) {
        	cpu.stack.push( ( val >> ( i * 8 ) ) & 0xff );
        } 
        return {};
    }

    // =============
    //  Execute Pop
    // =============

    std::expected<void,std::string> execute_pop( const x86_instruction& pop_instr, x86_cpu& cpu ) {
    	if ( !pop_instr.operands ) {
    		return std::unexpected( "Pop Instruction does not contain any Operands" );
    	}
    	if ( !pop_instr.operands->size() == 1 ) {
    		return std::unexpected( "Pop Instruction contains more than one Operand" );
    	}
	    auto& operands = pop_instr.operands.value();
	    int reg_width{};
	    bool unhandled = false;
	    std::optional<std::string> error;
	    std::visit( [ &reg_width, &unhandled, &error ]( auto&& op ) {
	        using T = std::decay_t<decltype( op )>;
	        if constexpr ( std::is_same_v<T,x86_register> ) {
	            if ( auto res = get_register_width( op ) ) {
	            	reg_width = res.value();
	            	return;
	            } else {
	            	error = res.error();
	            }
	        }
	        unhandled = true;
	    }, operands[ 0 ] );
	    if ( unhandled ) {
	    	if ( error.has_value() ) {
	    		return std::unexpected( error.value() );
	    	} else {
	    		return std::unexpected( "Unhandled Operand" );
	    	}
	    }
	    int size = reg_width / 8;
	    uint64_t val = 0;
	    for ( int i = 0; i < size; ++i ) {
	        if ( cpu.stack.empty() ) {
	            return std::unexpected( "Stack Underflow on POP" );
	        }
	        val |= static_cast<uint64_t>( cpu.stack.top() ) << ( i * 8 );
	        cpu.stack.pop();
	    }
	    std::visit( [ &cpu, val, &unhandled, &error ]( auto&& op ) {
	        using T = std::decay_t<decltype( op )>;
	        if constexpr ( std::is_same_v<T,x86_register> ) {
	            if ( auto res = cpu.set( op, val ) ) {
	            	return;
	            } else {
	            	error = res.error();
	            }
	        }
	        unhandled = true;
	    }, operands[ 0 ] );
	    if ( unhandled ) {
	    	if ( error.has_value() ) {
	    		return std::unexpected( error.value() );
	    	} else {
	    		return std::unexpected( "Unhandled Operand" );
	    	}
	    }
	    return {};
	}

	// ==============
    //  Execute Test
    // ==============

	std::expected<void,std::string> execute_test( const x86_instruction& test_instr, x86_cpu& cpu ) {
		if ( !test_instr.operands ) {
			return std::unexpected( "Test Instruction does not contain any Operands" );
		}
		if ( !test_instr.operands->size() != 2 ) {
			return std::unexpected( "Test Instruction does not contain two Operands" );
		}
    	auto& operands = test_instr.operands.value();
    	bool unhandled = false;
    	std::optional<std::string> error;
    	auto lhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto result = cpu.get( op ) ) {
        			return result.value();
        		} else {
        			error = result.error();
        		}        
    		}
    		unhandled = true;
    		return uint64_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Left-Hand Operand not handled" );
    		}
    	}
		auto rhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
			using T = std::decay_t<decltype( op )>;
			if constexpr ( std::is_same_v<T,x86_register> ) {
        		if ( auto result = cpu.get( op ) ) {
        			return result.value();
        		} else {
        			error = result.error();
        		}
    		}
    		unhandled = true;
    		return uint64_t{0};
		}, operands[ 1 ] );
		if ( unhandled ) {
			if ( error.has_value() ) {
				return std::unexpected( error.value() ); 
			} else {
				return std::unexpected( "Right-Hand Operand not handled" );
			}
		}
		uint64_t result = lhs & rhs;
		cpu.zero_flag = ( result == 0 );
		cpu.sign_flag = ( result >> 63 ) & 1;
   	 	cpu.carry_flag = false;
    	cpu.overflow_flag = false;
    	return {};
    }

    // =============
    //  Execute Shr
    // =============

    std::expected<void,std::string> execute_shr( const x86_instruction& shr_instr, x86_cpu& cpu ) {
    	if ( !shr_instr.operands.has_value() ) {
    		return std::unexpected( "Shr Instruction does not contain any Operands" );
    	}
    	auto& operands = shr_instr.operands.value();
    	bool unhandled = false;
    	std::optional<std::string> error;
    	auto lhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_immediate> ) {
    			return op.value;
    		}
    		unhandled = true;
    		return int64_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		return std::unexpected( "Left-Hand Operand not handled" );
    	}
    	auto rhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.get( op ) ) {
    				return res.value();
    			} else {
    				error = res.error();
    			}
    		}
    		unhandled = true;
    		return uint64_t{0};
    	}, operands[ 1  ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Right-Hand Operand not handled" );
    		}
    	}
    	uint64_t val = ( rhs >> lhs );
    	std::visit( [ &cpu, &val, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.set( op, val ) ) {
    				return;
    			} else {
    				error = res.error();
    			}
    		}
    		unhandled = true;
    	}, operands[ 1 ] );
    	return {};
    }

    // =============
    //  Execute Sar
    // =============

    std::expected<void,std::string> execute_sar( const x86_instruction& sar_instr, x86_cpu& cpu ) {
    	if ( !sar_instr.operands.has_value() ) {
    		return std::unexpected( "Sar Instruction does not contain any Operands" );
    	}
    	auto& operands = sar_instr.operands.value();
    	bool unhandled = false;
    	std::optional<std::string> error;
    	auto lhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_immediate> ) {
    			return op.value;
    		}
    		unhandled = true;
    		return int64_t{0};
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		return std::unexpected( "Left-Hand Operand not handled" );
    	}
    	auto rhs = std::visit( [ &cpu, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.get( op ) ) {
    				return static_cast<int64_t>( res.value() );
    			} else {
    				error = res.error();
    			}
    		}
    		unhandled = true;
    		return int64_t{0};
    	}, operands[ 1  ] );
    	if ( unhandled ) {
    		if ( error.has_value() ) {
    			return std::unexpected( error.value() );
    		} else {
    			return std::unexpected( "Right-Hand Operand not handled" );
    		}
    	}
    	uint8_t shift_count = lhs & 0x3f;
    	int64_t val = ( rhs >> shift_count );
    	std::visit( [ &cpu, &val, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.set( op, val ) ) {
    				return;
    			} else {
    				error = res.error();
    			}
    		}
    		unhandled = true;
    	}, operands[ 1 ] );
    	return {};
    }

    // =============
    //  Execute Ret
    // =============

    std::expected<void,std::string> execute_ret( const x86_instruction& ret_instr, x86_cpu& cpu ) {
    	if ( ret_instr.operands.has_value() && !ret_instr.operands->empty() ) {
    		return std::unexpected( "Ret Instruction contains Operands" );
    	}
    	constexpr int size = 8;
    	uint64_t val = 0;
    	for ( int i = 0; i < size; ++i ) {
    		if ( cpu.stack.empty() ) {
    			return std::unexpected( "Stack Underflow on RET" );
    		}
    		val |= static_cast<uint64_t>( cpu.stack.top() ) << ( i * 8 );
        	cpu.stack.pop();
    	}
    	cpu.rip = static_cast<int64_t>( val );
    	return {};
    }

    // =============
    //  Execute Lea
    // =============

    std::expected<void,std::string> execute_lea( const x86_instruction& lea_instr, x86_cpu& cpu ) {
    	auto& operands = lea_instr.operands.value();
    	bool unhandled = false;
    	std::optional<std::string> error;
    	uint64_t addr{};
    	std::visit( [ &cpu, &addr, &unhandled, &error ]( auto&& op ) { 
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_memory> ) {
    			if ( auto res = cpu.get( op.base.value() ) ) {
    				addr = res.value() + op.displacement.value();
    			} else {
    				error = res.error();
    			}
    		} else {
    			unhandled = true;
    		}
    	}, operands[ 0 ] ); 
    	if ( unhandled ) {
    		return std::unexpected( "LEA Left-Operand must be Memory" );
    	}
    	x86_register dest_reg;
    	std::visit( [ &cpu, &dest_reg, &unhandled ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			dest_reg = op;
    		} else {
    			unhandled = true;
    		}
    	}, operands[ 1 ] );
    	if ( unhandled ) {
    		return std::unexpected( "LEA Right-Operand must be a Register" );
    	}
    	if ( error.has_value() ) {
    		return std::unexpected( error.value() );
    	}
    	if ( auto res = cpu.set( dest_reg, addr ) ) {
    		return {};
    	} else {
    		return std::unexpected( res.error() );
    	}
    }

    // =============
    //  Execute Jne
    // =============

    std::expected<void,std::string> execute_jne( const x86_instruction& jne_instr, x86_cpu& cpu ) {
    	if ( cpu.zero_flag ) {
    		cpu.increment_rpi( jne_instr.machine_bytes.size() );
    	}
    	auto& operands = jne_instr.operands.value();
    	uint64_t addr{};
    	bool unhandled = false;
    	std::visit( [ &addr, &unhandled ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_address> ) {
    			addr = op.addr;
    			return;
    		}
    		unhandled = true;
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		return std::unexpected( "JNE Operand must be an Address" ); 
    	}
    	if ( auto res = cpu.set( x86_register::rip, addr ) ) {
    		return {};
    	} else {
    		return std::unexpected( res.error() );
    	}
    }

    // ============
    //  Execute Je
    // ============

    std::expected<void,std::string> execute_je( const x86_instruction& je_instr, x86_cpu& cpu ) {
    	if ( !cpu.zero_flag ) {
    		cpu.increment_rpi( je_instr.machine_bytes.size() );
    	}
    	auto& operands = je_instr.operands.value();
    	uint64_t addr{};
    	bool unhandled = false;
    	std::visit( [ &addr, &unhandled ]( auto&& op ) {
    		using T = std::decay_t<decltype( op )>;
    		if constexpr ( std::is_same_v<T,x86_address> ) {
    			addr = op.addr;
    			return;
    		}
    		unhandled = true;
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		return std::unexpected( "JNE Operand must be an Address" ); 
    	}
    	if ( auto res = cpu.set( x86_register::rip, addr ) ) {
    		return {};
    	} else {
    		return std::unexpected( res.error() );
    	}
    }

    // =============
    //  Execute Add
    // =============

    std::expected<void,std::string> execute_add( const x86_instruction& add_instr, x86_cpu& cpu ) {
    	auto& operands = add_instr.operands.value();
    	uint64_t val{};
    	bool unhandled = false;
    	std::optional<std::string> error;
    	std::visit( [ &cpu, &val, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype(op)>;
    		if constexpr ( std::is_same_v<T,x86_immediate> ) {
    			val = op.value;
    			return;
    		}
    		unhandled = true;
    	}, operands[ 0 ] );
    	if ( unhandled ) {
    		return std::unexpected( "Left-Hand Operand is not handled" );
    	}
    	uint64_t target_val{};
    	x86_register target_reg;
    	std::visit( [ &cpu, &target_val, &target_reg, &unhandled, &error ]( auto&& op ) {
    		using T = std::decay_t<decltype(op)>;
    		if constexpr ( std::is_same_v<T,x86_register> ) {
    			if ( auto res = cpu.get( op ) ) {
    				target_val = res.value();
    				target_reg = op;
    				return;
    			} else {
    				error = res.error();
    			}
    		}
    		unhandled = true;
    	}, operands[ 1 ] );
    	if ( unhandled ) {
    		return std::unexpected( "Right-Hand Operand is not handled" );
    	}
    	uint64_t result = target_val + val;
    	if ( auto res = cpu.set( target_reg, result ) ) {
    		return {};
    	} else {
    		return std::unexpected( res.error() );
    	}
    }

    // =======================
    //  Get Empty Line Offset
    // =======================

    int get_empty_line_offset( std::ifstream& file, std::size_t start_line ) {
    	std::streampos original_pos = file.tellg();
    	file.clear();
    	file.seekg(0);
    	std::string line;
    	std::size_t current = 0;
    	while ( current < start_line && std::getline( file, line ) ) {
    		++current;	
    	}
    	if ( current != start_line ) {
    		file.clear();
    		file.seekg( original_pos );
    		return -1;
    	}
    	int offset = 0;
    	while ( std::getline( file, line ) ) {
    		if ( line.empty() ) {
    			file.clear();
    			file.seekg( original_pos );
    			++offset;
    			return offset;
    		}
    		++offset;
    	}
    	file.clear();
    	file.seekg( original_pos );
    	return -1;
    }

    // ===========================
    //  Get Function Name Line No
    // ===========================

    std::optional<std::size_t> get_function_name_line_no( std::ifstream& file, const std::string& function_name ) {
    	std::string line;
    	std::size_t line_number = 0;
    	std::regex func_regex( "^0*([0-9A-Fa-f]{1,16})\\s+<" + function_name + ">:\\s*$" );
    	while ( std::getline( file, line ) ) {
    		++line_number;
    		if ( std::regex_search( line, func_regex ) ) {
    			return line_number;
    		}
    	} 
    	return std::nullopt;
    }

    // ==================
    //  Get Function Str
    // ==================

    std::expected<std::string,std::string> get_function_str( std::ifstream& file, const std::string& function_name ) {
    	std::string result;
    	auto line_no_opt = get_function_name_line_no( file, function_name );
    	if ( !line_no_opt ) {
    		return std::unexpected( "Function Name not found in File" );
    	}
    	auto& line_no = line_no_opt.value();
    	auto offset = get_empty_line_offset( file, line_no );
    	if ( offset == -1 ) {
    		return std::unexpected( "Error Calculating Empty Line Offset" );
    	}
    	std::string line;
    	file.clear();
    	file.seekg( 0 );
    	for ( std::size_t i = 0; i < line_no; ++i ) {
    		std::getline( file, line );
    	}
    	result += line + "\n";
    	while ( offset > 0 ) {
    		std::getline( file, line );
    		result += line;
    		if ( offset != 1 ) {
    			result += "\n";
    		}
    		--offset;
    	}
    	return result;
    }

    // ==================
    //  Extract Function
    // ==================

    std::expected<function,std::string> extract_function( const std::string& file_name, const std::string& function_name ) {
    	std::ifstream file( file_name );
    	if ( !file ) {
    		return std::unexpected( "Failed to Open File" );
    	}
    	auto res = get_function_str( file, function_name );
    	if ( !res ) {
    		return std::unexpected( "Failed to Extract Function String from File" );
    	}
    	auto& str = res.value();
    	auto parse_result = parse_function( str );
    	if ( !parse_result ) {
    		return std::unexpected( parse_result.error() );
    	}
    	return parse_result.value();
    }

    // ========================
    //  Extract Function Names
    // ========================

    std::expected<std::vector<std::string>,std::string> extract_function_names( const std::string& file_name ) {
    	std::vector<std::string> result;
    	std::ifstream file( file_name );
    	if ( !file ) {
    		return std::unexpected( "Failed to Open File" );
    	}
    	std::string line;
    	std::smatch match;
    	while ( std::getline( file, line ) ) {
    		if ( std::regex_search( line, match, func_name_regex ) ) {
    			result.push_back( match[ 1 ].str() );
    		}
    	}
    	return result;
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
	sss}

	*/

}