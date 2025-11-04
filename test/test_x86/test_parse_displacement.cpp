#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ParseDisplacement ) {
	int64_t expected = -4;
	auto displacement = stig::parse_displacement( "-0x4" );
	ASSERT_TRUE( displacement ) << displacement.error();
	EXPECT_EQ( displacement.value(), expected );
}