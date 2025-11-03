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

TEST( UnitTest, ParseX86Instruction_Push ) {
	std::string push_instruction = "112d:	55                   	push   %rbp";
	stig::x86_instruction expected = {
		0x112d,
		std::vector<uint8_t>{ 0x55 },
		stig::x86_mnemonic::push,
		std::vector<stig::x86_operand>{ stig::x86_register::rbp }
	};
	auto parse_result = stig::parse_x86_instruction( push_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Mov ) {
	std::string mov_instruction = "112e:	48 89 e5             	mov    %rsp,%rbp";
	stig::x86_instruction expected = {
		0x112e,
		std::vector<uint8_t>{ 0x48, 0x89, 0xe5 },
		stig::x86_mnemonic::mov,
		std::vector<stig::x86_operand>{ stig::x86_register::rsp, stig::x86_register::rbp }
	};
	auto parse_result = stig::parse_x86_instruction( mov_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}