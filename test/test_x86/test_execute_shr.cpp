#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteShr ) {
	stig::x86_instruction instr = {
		0,
		std::vector<uint8_t>{},
		stig::x86_mnemonic::shr,
		std::vector<stig::x86_operand>{ stig::x86_immediate{ 0x3f }, stig::x86_register::rsi }
	};
	stig::x86_cpu cpu{};
	auto set_result = cpu.set( stig::x86_register::rsi, 0x8000000000000000 );
	ASSERT_TRUE( set_result ) << set_result.error();
	auto shr_result = stig::execute_shr( instr, cpu );
	ASSERT_TRUE( shr_result ) << shr_result.error();
	auto get_result = cpu.get( stig::x86_register::rsi );
	EXPECT_EQ( get_result.value(), 0x0000000000000001 );
} 