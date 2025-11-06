#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteXor ) {
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{ 0x31, 0xed },
		stig::x86_mnemonic::xor_,
		std::vector<stig::x86_operand>{ stig::x86_register::edx, stig::x86_register::edx }
	};
	stig::x86_cpu cpu{};
	cpu.set( stig::x86_register::edx, 0x55555555 );
	auto xor_res = stig::execute_xor( instr, cpu );
	ASSERT_TRUE( xor_res ) << xor_res.error();
	auto result = cpu.get( stig::x86_register::edx );
	ASSERT_TRUE( result ) << result.error();
	EXPECT_EQ( result.value(), 0x00000000 );
}