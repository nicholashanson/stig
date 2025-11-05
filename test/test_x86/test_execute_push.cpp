#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecutePush ) {
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{ 0x50 },
		stig::x86_mnemonic::push,
		std::vector<stig::x86_operand>{ stig::x86_register::rax }
	};
	stig::x86_cpu cpu;
	cpu.set( stig::x86_register::rdx, 0x5555555555555555 );
	stig::execute_push( instr, cpu );
	EXPECT_EQ( cpu.stack.size(), 8 );
}
