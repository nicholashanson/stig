#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExtractMachineBytes ) {
	stig::x86_instruction_parse_result parse_result_before = {
		{}, "1129:	f3 0f 1e fa          	endbr64", 5
	};
	auto parse_result = stig::extract_machine_bytes( parse_result_before );
	ASSERT_TRUE( parse_result ) << parse_result.error();
	auto& parse_result_after = parse_result.value();
	std::vector<uint8_t> expected_machine_bytes = { 0xf3, 0x0f, 0x1e, 0xfa };
	EXPECT_EQ( parse_result_after.instruction.machine_bytes, expected_machine_bytes );
	EXPECT_EQ( parse_result_after.pos, 17 );
}