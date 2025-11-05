#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteCmp ) {
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{ 0x48, 0x39, 0xf8 },
		stig::x86_mnemonic::cmp,
		std::vector<stig::x86_operand>{ stig::x86_register::rdi, stig::x86_register::rax }
	};
	{
		stig::x86_cpu cpu;
		cpu.set( stig::x86_register::rdi, 0x01 );
		cpu.set( stig::x86_register::rax, 0x01 );
		stig::execute_cmp( instr, cpu );
		EXPECT_TRUE( cpu.zero_flag );
	}
	{
		stig::x86_cpu cpu;
		cpu.set( stig::x86_register::rdi, 0x02 );
		cpu.set( stig::x86_register::rax, 0x01 );
		stig::execute_cmp( instr, cpu );
		EXPECT_FALSE( cpu.zero_flag );
		EXPECT_FALSE( cpu.carry_flag );
	}
	{
		stig::x86_cpu cpu;
		cpu.set( stig::x86_register::rdi, 0x01 );
		cpu.set( stig::x86_register::rax, 0x02 );
		stig::execute_cmp( instr, cpu );
		EXPECT_TRUE( cpu.carry_flag );
	}
}