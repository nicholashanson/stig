#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, GetMemory ) {
	auto memory_str = "-0x4(%rbp)";
	stig::x86_memory expected = { stig::x86_register::rbp, std::nullopt, std::nullopt, -4 };
	auto result = stig::get_memory( memory_str );
	ASSERT_TRUE( result ) << result.error();
	EXPECT_EQ( result.value(), expected );
}