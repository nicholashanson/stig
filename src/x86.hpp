#ifndef X86_HPP
#define X86_HPP

#include <charconv>
#include <cstdint>
#include <expected>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace stig {

	enum class x86_mnemonic : uint8_t  {
		add,
		endbr64,
		mov,
		pop,
		push,
		ret
	};

	enum class x86_register : uint8_t {
		edi,
		rbp,
		rsp
	};

	struct x86_immediate {
		uint64_t value;

		bool operator==( const x86_immediate& other ) const {
			return value == other.value;
		}
	};

	struct x86_memory {
    	std::optional<x86_register> base;    
    	std::optional<x86_register> index;      
    	std::optional<uint8_t> scale;           
    	std::optional<int64_t> displacement;  

    	bool operator==( const x86_memory& other ) const {
    		return base == other.base &&
    			   index == other.index &&
    			   scale == other.scale &&
    			   displacement == other.displacement;
    	}  
	};

	using x86_operand = std::variant<x86_register,x86_immediate,x86_memory>;

	struct x86_instruction {
		uint64_t address;
		std::vector<uint8_t> machine_bytes;
		x86_mnemonic mnemonic;
		std::optional<std::vector<x86_operand>> operands;

		bool operator==( const x86_instruction& other ) const {
			return address == other.address &&
				   machine_bytes == other.machine_bytes &&
				   mnemonic == other.mnemonic &&
				   operands == other.operands;	
		}
	};

	struct x86_instruction_parse_result {
		x86_instruction instruction;
		std::string_view buffer;
		std::size_t pos;
	};

	std::expected<x86_instruction_parse_result,std::string> parse_x86_instruction( std::string instruction );

	std::expected<x86_instruction_parse_result,std::string> parse_address( x86_instruction_parse_result p_result );

	std::expected<x86_instruction_parse_result,std::string> extract_machine_bytes( x86_instruction_parse_result p_result );

	std::vector<std::string> split_token( const std::string& token );

	std::expected<int64_t,std::string> parse_displacement( const std::string& token );

	std::expected<x86_memory,std::string> get_memory( const std::string& token );

	//std::ostream& operator<<( std::ostream& os, x86_instruction instruction );

}

#endif // X86_HPP