#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ParseAddress ) {
	stig::x86_instruction_parse_result parse_result_before = {
		{}, "1129:	f3 0f 1e fa          	endbr64", 0
	};
	auto parse_result = stig::parse_address( parse_result_before );
	auto& parse_result_after = parse_result.value();
	EXPECT_EQ( parse_result_after.instruction.address, 0x1129 );
	EXPECT_EQ( parse_result_after.pos, 5 );
}