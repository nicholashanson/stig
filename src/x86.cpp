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
	        	break;
	        }
	        p_result.pos += 2;
	        uint8_t value = static_cast<uint8_t>( std::stoul( token, nullptr, 16 ) );
	        bytes.push_back( value );
	    }
	    p_result.pos += bytes.size();
	    p_result.instruction.machine_bytes = std::move( bytes );
	    return p_result;
    } 

    // ================
    //  Parse Mnemonic
    // ================

    std::expected<x86_instruction_parse_result,std::string> parse_mnemonic( x86_instruction_parse_result p_result ) {
    	std::istringstream iss( std::string( p_result.buffer ) );
	    std::string token;
	    iss.seekg( p_result.pos, std::ios::beg );
	    iss >> token;
 	    if ( token == "endbr64" ) {
	    	p_result.instruction.mnemonic = x86_mnemonic::endbr64;
	    }
	    if ( token == "push" ) {
	    	p_result.instruction.mnemonic = x86_mnemonic::push;
	    }
	    p_result.pos = iss.tellg();
	    ++p_result.pos; 
	    return p_result;
    }

    // ==============
    //  Get Register
    // ==============

    std::optional<x86_register> get_register( const std::string& token ) {
    	if ( token == "%rbp" ) return x86_register::rbp;
    	return std::nullopt;
    }

    // ===============
    //  Get Immediate
    // ===============

    std::optional<x86_immediate> get_immediate( const std::string& token ) {
    	return std::nullopt;
    }

    // ================
    //  Parse Operands
    // ================

    std::expected<x86_instruction_parse_result,std::string> parse_operands( x86_instruction_parse_result p_result ) {
    	if ( p_result.instruction.mnemonic == x86_mnemonic::endbr64 ) {
    		return p_result;
    	}
    	std::string token;
    	std::istringstream iss( std::string( p_result.buffer ) );
    	iss.seekg( p_result.pos, std::ios::beg );
    	while ( iss >> token ) {
	        auto register_result = get_register( token );
	        if ( register_result ) {
	        	p_result.instruction.operands.emplace();
	        	p_result.instruction.operands->push_back( register_result.value() );
	        	continue;
	        }
	        auto immediate_result = get_immediate( token );
	        if ( immediate_result ) {
	        	p_result.instruction.operands->push_back( immediate_result.value() );
	        	continue;
	        }
	        break;
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
			.and_then( parse_operands );
	}

}