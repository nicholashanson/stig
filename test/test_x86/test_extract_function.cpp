#include <gtest/gtest.h>

#include <x86.hpp>

#include "test_constants.hpp"

TEST( UnitTest, ExtractFunction ) {
	auto res = stig::extract_function( "../test/main_disasm.txt", "main" );
	ASSERT_TRUE( res ) << res.error();
	EXPECT_EQ( res.value(), test::expected_main );
}