#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, GetImmediate ) {
	std::string imm = "$0xfffffffffffffff0";
	auto res = stig::get_immediate( imm );
	ASSERT_TRUE( res ) << "Failed to convert";
	EXPECT_EQ( res.value().value, 0xfffffffffffffff0 );
}

