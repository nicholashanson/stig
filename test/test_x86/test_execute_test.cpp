#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteTest ) {
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{ 0x48, 0x85, 0xc0 },
		stig::x86_mnemonic::test,
		std::vector<stig::x86_operand>{ stig::x86_register::eax, stig::x86_register::eax }
	};
	stig::x86_cpu cpu;
	cpu.set( stig::x86_register::eax, 0x01 );
	stig::execute_test( instr, cpu );
	EXPECT_TRUE( cpu.zero_flag );
}