#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteJne ) {
	stig::x86_address target = { 0x00000000000000f };
	stig::x86_instruction instr = {
		0,
		std::vector<uint8_t>{ 0x75, 0x2b },
		stig::x86_mnemonic::jne,
		std::vector<stig::x86_operand>{ target }
	};
	stig::x86_cpu cpu{};
	cpu.zero_flag = true;
	auto jne_result = stig::execute_jne( instr, cpu );
	ASSERT_TRUE( jne_result ) << jne_result.error();
	auto get_result = cpu.get( stig::x86_register::rip );
	ASSERT_TRUE( get_result ) << get_result.error();
	EXPECT_EQ( get_result.value(), target.addr );
}