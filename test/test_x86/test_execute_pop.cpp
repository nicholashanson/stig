#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecutePop ) {
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{},
		stig::x86_mnemonic::pop,
		std::vector<stig::x86_operand>{ stig::x86_register::rax }
	};
	stig::x86_cpu cpu{};
	for ( int i = 0; i < 8; ++i ) {
		cpu.stack.push( 0x55 );
	}
	auto pop_result = stig::execute_pop( instr, cpu );
	ASSERT_TRUE( pop_result ) << pop_result.error();
	auto result = cpu.get( stig::x86_register::rax );
	EXPECT_EQ( result, 0x5555555555555555 );
}
