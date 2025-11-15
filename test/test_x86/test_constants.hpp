#ifndef TEST_CONSTANTS_HPP
#define TEST_CONSTANTS_HPP

#include <x86.hpp>

using namespace stig;

namespace test {

	inline function expected_main {
    	"main",
	    {
	        { 0x1141, { 0xf3,0x0f,0x1e,0xfa }, x86_mnemonic::endbr64, std::nullopt },
	        { 0x1145, { 0x55 }, x86_mnemonic::push, std::vector{ x86_operand{ x86_register::rbp } } },
	        { 0x1146, { 0x48,0x89,0xe5 }, x86_mnemonic::mov, std::vector{ x86_operand{ x86_register::rsp }, x86_operand{x86_register::rbp } } },
	        { 0x1149, { 0xb8,0x00,0x00,0x00,0x00 }, x86_mnemonic::mov, std::vector{ x86_operand{ x86_immediate{ 0x0 } }, x86_operand{ x86_register::eax } } },
	        { 0x114e, { 0x5d }, x86_mnemonic::pop, std::vector{ x86_operand{ x86_register::rbp } } },
	        { 0x114f, { 0xc3 }, x86_mnemonic::ret, std::nullopt }
	    }
	};

} // namespace test


#endif // TEST_CONSTANTS_HPP