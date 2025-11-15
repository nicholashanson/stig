#include <gtest/gtest.h>

#include <x86.hpp>

#include "test_constants.hpp"

TEST( UnitTest, ConvertToProgram ) {
	auto program_result = stig::convert_to_program( test::expected_main );
	ASSERT_TRUE( program_result ) << program_result.error();
	EXPECT_EQ( program_result.value().instrs.size(), 6 ); 
}