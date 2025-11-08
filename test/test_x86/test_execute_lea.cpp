#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteLea ) {
	stig::x86_memory mem = {
		stig::x86_register::rip,
		std::nullopt,
		std::nullopt,
		0x2f62
	};
	stig::x86_instruction instr{ 
		0,
		std::vector<uint8_t>{},
		stig::x86_mnemonic::lea,
		std::vector<stig::x86_operand>{ mem, stig::x86_register::rsi }
	};
	stig::x86_vm vm{};
	auto set_result = vm.cpu.set( stig::x86_register::rip, 0x000000000000000f );
	ASSERT_TRUE( set_result ) << set_result.error();
	auto lea_result = stig::execute_lea( instr, vm.cpu );
	ASSERT_TRUE( lea_result ) << lea_result.error();
	auto get_result = vm.cpu.get( stig::x86_register::rsi );
	EXPECT_EQ( get_result.value(), 0x000000000000000f + 0x2f62 );
}