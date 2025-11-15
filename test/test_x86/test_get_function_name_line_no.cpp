#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, GetFunctionNameLineNo ) {
	std::ifstream file( "../test/main_static.txt" );
	std::size_t expected = 7;
	auto line_no_opt = stig::get_function_name_line_no( file, "_init" );
	ASSERT_TRUE( line_no_opt ) << "Function Name not found";
	auto result = line_no_opt.value();
	EXPECT_EQ( result, expected );
}