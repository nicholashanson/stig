#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, GetEmptyLineOffset ) {
	std::ifstream file( "../test/main_static.txt" );
	ASSERT_TRUE( file );
	std::size_t function_name_line = 7;
	int expected_offset = 9;
	auto result = stig::get_empty_line_offset( file, function_name_line );
	EXPECT_EQ( result, expected_offset );
}