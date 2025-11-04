#ifndef X86_HPP
#define X86_HPP

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <expected>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace stig {

	namespace file_format {
		inline std::string x_86_64 = "file format elf64-x86-64";
	};

	enum class x86_mnemonic : uint8_t  {
		add,
		and_,
		call,
		cmp,
		cmpb,
		cmpq,
		endbr64,
		hlt,
		je,
		jne,
		jmp,
		lea,
		mov,
		movb,
		padding,
		nopl,
		nopw,
		pop,
		push,
		ret,
		sub,
		sar,
		shr,
		test,
		xor_
	};

	inline const std::unordered_map<x86_mnemonic,std::string> mnemonic_names = {
    	{ x86_mnemonic::endbr64, "endbr64" },
	    { x86_mnemonic::push,       "push" },
	    { x86_mnemonic::mov,         "mov" },
	    { x86_mnemonic::pop,         "pop" },
	    { x86_mnemonic::ret,         "ret" },
	    { x86_mnemonic::nopl,       "nopl" },
	    { x86_mnemonic::movb,       "movb" },
	    { x86_mnemonic::call,       "call" },
	    { x86_mnemonic::cmpq,       "cmpq" },
	    { x86_mnemonic::lea,         "lea" },
	    { x86_mnemonic::sar,         "sar" },
	    { x86_mnemonic::je,           "je" },
	    { x86_mnemonic::add,         "add" },
	    { x86_mnemonic::sub,         "sub" },
	    { x86_mnemonic::jmp,         "jmp" },
	    { x86_mnemonic::cmpb,       "cmpb" },
	    { x86_mnemonic::jne, 		 "jne" },
	    { x86_mnemonic::padding, "padding" },
	    { x86_mnemonic::shr,         "shr" },
	    { x86_mnemonic::test,       "test" },
	  	{ x86_mnemonic::nopw,       "nopw" },
	  	{ x86_mnemonic::cmp,         "cmp" },
	  	{ x86_mnemonic::xor_,        "xor" },
	  	{ x86_mnemonic::and_,        "and" },
	  	{ x86_mnemonic::hlt,         "hlt" }    
    };

    static const std::unordered_map<std::string, x86_mnemonic> mnemonic_map = {
    	{ "add",         x86_mnemonic::add },
	    { "endbr64", x86_mnemonic::endbr64 },
	    { "push",       x86_mnemonic::push },
	    { "mov",         x86_mnemonic::mov },
	    { "pop",         x86_mnemonic::pop },
	    { "ret",         x86_mnemonic::ret },
	    { "nopl",       x86_mnemonic::nopl },
	    { "movb",       x86_mnemonic::movb },
	    { "call",       x86_mnemonic::call },
	    { "cmpq",       x86_mnemonic::cmpq },
	    { "lea",         x86_mnemonic::lea },
	    { "sar",         x86_mnemonic::sar },
	    { "je",           x86_mnemonic::je },
	    { "sub",         x86_mnemonic::sub },
	    { "jmp",         x86_mnemonic::jmp },
	    { "cmpb",       x86_mnemonic::cmpb },
	    { "jne",         x86_mnemonic::jne },
	    { "padding", x86_mnemonic::padding },
	    { "shr",         x86_mnemonic::shr },
	    { "test",       x86_mnemonic::test },
	    { "nopw",       x86_mnemonic::nopw },
	    { "cmp",         x86_mnemonic::cmp },
	    { "xor",        x86_mnemonic::xor_ },
	    { "and",        x86_mnemonic::and_ },
	    { "hlt",         x86_mnemonic::hlt }
	};

	enum class x86_register : uint8_t {
		eax,
		edx,
		edi,
		esi,
		rax,
		rbp,
		rdi,
		rip,
		rsi,
		rsp
	};

	struct x86_immediate {
		int64_t value;

		bool operator==( const x86_immediate& other ) const {
			return value == other.value;
		}
	};

	struct x86_address {
		uint64_t addr;

		bool operator==( const x86_address& other ) const {
			return addr == other.addr;
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

	using x86_operand = std::variant<x86_register,x86_immediate,x86_memory,x86_address>;

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

	struct function {
		std::string name;
		std::vector<x86_instruction> instructions;
	};

	struct elf64_x86_64 {
		std::vector<function> _init;
		std::vector<function> plt;
		std::vector<function> plt_got;
		std::vector<function> text;
		std::vector<function> fini;
	};

	std::expected<x86_instruction_parse_result,std::string> parse_x86_instruction( std::string instruction );

	std::expected<x86_instruction_parse_result,std::string> parse_address( x86_instruction_parse_result p_result );

	std::expected<x86_instruction_parse_result,std::string> extract_machine_bytes( x86_instruction_parse_result p_result );

	std::vector<std::string> split_token( const std::string& token );

	std::expected<int64_t,std::string> parse_displacement( const std::string& token );

	std::expected<x86_memory,std::string> get_memory( const std::string& token );

	std::expected<function,std::string> parse_function( const std::string& token );

	//std::ostream& operator<<( std::ostream& os, x86_instruction instruction );

}

#endif // X86_HPP