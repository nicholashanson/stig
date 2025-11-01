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

	enum class x86_operand : uint8_t {};

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

}

#endif // X86_HPP