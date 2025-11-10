#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExecuteAdd ) {
    stig::x86_immediate immediate = { 0x08 };
    stig::x86_instruction instr = {
        0,
        std::vector<uint8_t>{ 0x48, 0x83, 0xc4, 0x08 },
        stig::x86_mnemonic::add,
        std::vector<stig::x86_operand>{ immediate, stig::x86_register::rsp }
    };
    stig::x86_cpu cpu{};
    auto set_result = cpu.set( stig::x86_register::rsp, 0x0000000000000000f );
    auto add_result = stig::execute_add( instr, cpu );
    ASSERT_TRUE( add_result ) << add_result.error();
    auto get_result = cpu.get( stig::x86_register::rsp );
    ASSERT_TRUE( get_result ) << get_result.error();
    EXPECT_EQ( get_result.value(), 0x00000000000000f + 0x08 );
}