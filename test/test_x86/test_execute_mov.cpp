#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteMov ) {
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{ 0x49, 0x89, 0xd1 },
		stig::x86_mnemonic::mov,
		std::vector<stig::x86_operand>{ stig::x86_register::rdx, stig::x86_register::r9 }
	};
	stig::x86_cpu cpu;
	cpu.set( stig::x86_register::rdx, 0x01 );
	cpu.set( stig::x86_register::r9, 0x02 );
	stig::execute_mov( instr, cpu );
	auto result = cpu.get( stig::x86_register::r9 );
	EXPECT_EQ( result, 0x01 );
}