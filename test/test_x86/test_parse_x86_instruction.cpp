#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ParseX86Instruction ) {
	std::string endbr64_instruction = "1129:	f3 0f 1e fa          	endbr64";
	stig::x86_instruction expected = {
		0x1129,
		std::vector<uint8_t>{ 0xf3, 0x0f, 0x1e, 0xfa },
		stig::x86_mnemonic::endbr64,
		std::nullopt
	};
	auto parse_result = stig::parse_x86_instruction( endbr64_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}