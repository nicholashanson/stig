#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteSar ) {
	stig::x86_instruction instr = {
		0,
		std::vector<uint8_t>{},
		stig::x86_mnemonic::sar,
		std::vector<stig::x86_operand>{ stig::x86_immediate{ 0x3 }, stig::x86_register::rax }
	};
	stig::x86_cpu cpu{};
	auto set_result = cpu.set( stig::x86_register::rax, 0x8000000000000000 );
	ASSERT_TRUE( set_result ) << set_result.error();
	auto sar_result = stig::execute_sar( instr, cpu );
	ASSERT_TRUE( sar_result ) << sar_result.error();
	auto get_result = cpu.get( stig::x86_register::rax );
	EXPECT_EQ( get_result.value(), 0xf000000000000000 );
} 