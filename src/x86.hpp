#ifndef X86_HPP
#define X86_HPP

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <expected>
#include <iostream>
#include <optional>
#include <stack>
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
		ebp,
		edx,
		edi,
		esi,
		rax,
		rbp,
		rdi,
		rdx,
		rip,
		rsi,
		rsp,
		r8, 
		r9, 
		r10, 
		r11, 
		r12, 
		r13, 
		r14, 
		r15
	};

	inline std::expected<int,std::string> get_register_width( const x86_register reg ) {
	    switch ( reg ) {
	        case x86_register::rax:
	        case x86_register::rbp:
	        case x86_register::rdi:
	        case x86_register::rip:
	        case x86_register::rsi:
	        case x86_register::rsp:
	        case x86_register::r8:
	        	return 64;
	        case x86_register::eax: 
	        case x86_register::ebp: 
	        case x86_register::edx:
	        case x86_register::edi:
	        case x86_register::esi:
	        	return 32;
	        default:
	        	return std::unexpected( "Register Width not found" );
	    }
	}

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

	struct x86_cpu {
		int64_t rax;
		int64_t rbp;
		int64_t	rdi;
		int64_t rdx;
		int64_t	rip;
		int64_t	rsi;
		int64_t	rsp;
		int64_t r8; 
		int64_t r9; 
		int64_t r10; 
		int64_t r11; 
		int64_t r12; 
		int64_t r13; 
		int64_t r14; 
		int64_t r15;

		std::stack<uint8_t> stack;

		void increment_rpi( const int val ) {
			rip += val;
		}
 
		bool zero_flag = false;
		bool carry_flag = false;
		bool sign_flag = false;
		bool overflow_flag = false;

		std::expected<uint64_t,std::string> get( const x86_register reg ) {
			switch ( reg ) {
				case x86_register::ebp:
					return static_cast<uint32_t>( rbp );
				case x86_register::edx:
					return static_cast<uint32_t>( rdx );
				case x86_register::rax:
					return static_cast<uint64_t>( rax );
				case x86_register::rdi:
					return static_cast<uint64_t>( rdi );
				case x86_register::rdx:
					return static_cast<uint64_t>( rdx );
				case x86_register::rip:
					return static_cast<uint64_t>( rip );
				case x86_register::rsp:
					return static_cast<uint64_t>( rsp );
				case x86_register::rsi:
					return static_cast<uint64_t>( rsi );
				case x86_register::r9:
					return static_cast<uint64_t>( r9 );
				default:
					return std::unexpected( "Unimplemented Register" ); 
			}
		}

		std::expected<void,std::string> set( const x86_register reg, uint64_t val ) {
			switch ( reg ) {
				case x86_register::ebp: {
					uint32_t low = static_cast<uint32_t>( val );
            		rbp = static_cast<int64_t>( static_cast<uint64_t>( low ) );
            		return {};
            	}
            	case x86_register::edx: {
            		uint32_t low = static_cast<uint32_t>( val );
            		rdx = static_cast<int64_t>( static_cast<uint64_t>( low ) );
            		return {};
            	}
            	case x86_register::rax: {
            		rax = static_cast<int64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	}
            	case x86_register::rdi: {
            		rdi = static_cast<int64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	} 
            	case x86_register::rdx: {
            		rdx = static_cast<int64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	}
            	case x86_register::rip: {
            		rip = static_cast<int64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	} 
            	case x86_register::rsi: {
            		rsi = static_cast<int64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	}
            	case x86_register::rsp: {
            		rsp = static_cast<uint64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	} 
            	case x86_register::r9: {
            		r9 = static_cast<int64_t>( static_cast<uint64_t>( val ) );
            		return {};
            	}
				default:
					return std::unexpected( "Unimplemented Register" );
			}
		}
	};

	std::expected<void,std::string> execute_add( const x86_instruction& add_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_and( const x86_instruction& and_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_call( const x86_instruction& call_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_cmp( const x86_instruction& cmp_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_cmpb( const x86_instruction& cmpb_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_cmpq( const x86_instruction& cmpq_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_endbr64( const x86_instruction& endbr64_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_hlt( const x86_instruction& hlt_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_je( const x86_instruction& je_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_jne( const x86_instruction& jne_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_jmp( const x86_instruction& jmp_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_lea( const x86_instruction& lea_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_mov( const x86_instruction& mov_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_movb( const x86_instruction& movb_instr, x86_cpu& cpu, std::unordered_map<uint64_t,uint8_t>& ram );

	std::expected<void,std::string> execute_nopl( const x86_instruction& nopl_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_nopw( const x86_instruction& nopw_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_padding( const x86_instruction& padding_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_pop( const x86_instruction& pop_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_push( const x86_instruction& push_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_ret( const x86_instruction& ret_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_sar( const x86_instruction& sar_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_shr( const x86_instruction& shr_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_test( const x86_instruction& test_instr, x86_cpu& cpu );

	std::expected<void,std::string> execute_xor( const x86_instruction& xor_instr, x86_cpu& cpu );

	struct x86_vm {
		x86_cpu cpu;
		std::unordered_map<uint64_t,uint8_t> ram;

		std::expected<void,std::string> execute_instruction( x86_instruction& instruction ) {
			switch ( instruction.mnemonic ) {
		/*0*/	case x86_mnemonic::add:
					return execute_add( instruction, cpu );
		/*1*/	case x86_mnemonic::and_:
					return execute_and( instruction, cpu );
		/*2*/	case x86_mnemonic::call:
					return execute_call( instruction, cpu );
		/*3*/	case x86_mnemonic::cmp:
					return execute_cmp( instruction, cpu );
		/*4*/	case x86_mnemonic::cmpb:
					return execute_cmpb( instruction, cpu );
		/*5*/	case x86_mnemonic::cmpq:
					return execute_cmpq( instruction, cpu );
		/*6*/	case x86_mnemonic::endbr64:
					return execute_endbr64( instruction, cpu );
		/*7*/	case x86_mnemonic::hlt:
					return execute_hlt( instruction, cpu );
		/*8*/	case x86_mnemonic::je:
					return execute_je( instruction, cpu );
		/*9*/	case x86_mnemonic::jmp:
					return execute_jmp( instruction, cpu );
		/*10*/	case x86_mnemonic::jne:
					return execute_jne( instruction, cpu );
		/*11*/	case x86_mnemonic::lea:
					return execute_lea( instruction, cpu );
		/*12*/	case x86_mnemonic::mov:
					return execute_mov( instruction, cpu );
		/*13*/	case x86_mnemonic::movb:
					return execute_movb( instruction, cpu, ram );
		/*14*/	case x86_mnemonic::nopl:
					return execute_nopl( instruction, cpu );
		/*15*/	case x86_mnemonic::nopw:
					return execute_nopw( instruction, cpu );
		/*16*/	case x86_mnemonic::padding:
					return execute_padding( instruction, cpu );
		/*17*/	case x86_mnemonic::pop:
					return execute_pop( instruction, cpu );
		/*18*/	case x86_mnemonic::push:
					return execute_push( instruction, cpu );
		/*19*/	case x86_mnemonic::ret:
					return execute_ret( instruction, cpu );
		/*20*/	case x86_mnemonic::sar:
					return execute_sar( instruction, cpu );
		/*21*/	case x86_mnemonic::shr:
					return execute_shr( instruction, cpu );
		/*22*/	case x86_mnemonic::test:
					return execute_test( instruction, cpu );
		/*23*/	case x86_mnemonic::xor_:
					return execute_xor( instruction, cpu );
				default:
					return std::unexpected( "Unimplemented instruction" );
			}
		}
	};

} // namespace stig

#endif // X86_HPP