#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteRet ) {
	stig::x86_instruction instr = {
		0,
		std::vector<uint8_t>{},
		stig::x86_mnemonic::ret,
		std::nullopt
	};
	stig::x86_cpu cpu{};
	auto set_rip_result = cpu.set( stig::x86_register::rip, 0x80000000ffffffff );
	ASSERT_TRUE( set_rip_result ) << set_rip_result.error();
	cpu.stack.push( 0x00 );
	cpu.stack.push( 0x00 );
	cpu.stack.push( 0x00 );
	cpu.stack.push( 0x00 );
	cpu.stack.push( 0x00 );
	cpu.stack.push( 0x00 );
	cpu.stack.push( 0xff );
	cpu.stack.push( 0xff );
	auto ret_result = stig::execute_ret( instr, cpu );
	ASSERT_TRUE( ret_result ) << ret_result.error();
	auto get_result = cpu.get( stig::x86_register::rip );
	EXPECT_EQ( get_result.value(), 0x000000000000ffff );
} 