#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, SplitToken ) {
	std::string token = "%rsp,%rbp";
	auto operands = stig::split_token( token );
	std::vector<std::string> expected = { "%rsp", "%rbp" };
	EXPECT_EQ( operands, expected );
}