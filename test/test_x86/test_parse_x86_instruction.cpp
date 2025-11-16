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

TEST( UnitTest, ParseX86Instruction_Mov_Memory ) {
	std::string mov_instruction = "1131:	89 7d fc             	mov    %edi,-0x4(%rbp)";
	stig::x86_memory expected_mem = {
		stig::x86_register::rbp,
		std::nullopt,
		std::nullopt,
		-4
	};
	stig::x86_instruction expected = {
		0x1131,
		std::vector<uint8_t>{ 0x89, 0x7d, 0xfc },
		stig::x86_mnemonic::mov,
		std::vector<stig::x86_operand>{ stig::x86_register::edi, expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( mov_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Mov_Esi ) {
	std::string mov_instruction = "1134:	89 75 f8             	mov    %esi,-0x8(%rbp)";
	stig::x86_memory expected_mem = {
		stig::x86_register::rbp,
		std::nullopt,
		std::nullopt,
		-8
	};
	stig::x86_instruction expected = {
		0x1134,
		std::vector<uint8_t>{ 0x89, 0x75, 0xf8 },
		stig::x86_mnemonic::mov,
		std::vector<stig::x86_operand>{ stig::x86_register::esi, expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( mov_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Add ) {
	std::string add_instruction = "113d:	01 d0                	add    %edx,%eax";
	stig::x86_instruction expected = {
		0x113d,
		std::vector<uint8_t>{ 0x01, 0xd0 },
		stig::x86_mnemonic::add,
		std::vector<stig::x86_operand>{ stig::x86_register::edx, stig::x86_register::eax }
	};
	auto parse_result = stig::parse_x86_instruction( add_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Pop ) {
	std::string pop_instruction = "113f:	5d                   	pop    %rbp";
	stig::x86_instruction expected = {
		0x113f,
		std::vector<uint8_t>{ 0x5d },
		stig::x86_mnemonic::pop,
		std::vector<stig::x86_operand>{ stig::x86_register::rbp }
	};
	auto parse_result = stig::parse_x86_instruction( pop_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Ret ) {
	std::string ret_instruction = "1140:	c3                   	ret";
	stig::x86_instruction expected = {
		0x1140,
		std::vector<uint8_t>{ 0xc3 },
		stig::x86_mnemonic::ret,
		std::nullopt
	};
	auto parse_result = stig::parse_x86_instruction( ret_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Nopl ) {
	std::string nopl_instruction = "1119:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)";
	stig::x86_memory expected_mem {
		stig::x86_register::rax,
		std::nullopt,
		std::nullopt,
		0
	};
	stig::x86_instruction expected = {
		0x1119,
		std::vector<uint8_t>{ 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 },
		stig::x86_mnemonic::nopl,
		std::vector<stig::x86_operand>{ expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( nopl_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Nopl_Memory ) {
	std::string nopl_instruction = "1115:	0f 1f 00             	nopl   (%rax)";
	stig::x86_memory expected_mem {
		stig::x86_register::rax,
		std::nullopt,
		std::nullopt,
		std::nullopt
	};
	stig::x86_instruction expected = {
		0x1115,
		std::vector<uint8_t>{ 0x0f, 0x1f, 0x00 },
		stig::x86_mnemonic::nopl,
		std::vector<stig::x86_operand>{ expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( nopl_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Nopw ) {
	std::string nopw_instruction = "1066:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)";
	stig::x86_memory expected_mem {
		stig::x86_register::rax,
		stig::x86_register::rax,
		1,
		0x00
	};
	stig::x86_instruction expected = {
		0x1066,
		std::vector<uint8_t>{ 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00 },
		stig::x86_mnemonic::nopw,
		std::vector<stig::x86_operand>{ expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( nopw_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Movb ) {
	std::string movb_instruction = "110c:	c6 05 fd 2e 00 00 01 	movb   $0x1,0x2efd(%rip)        # 4010 <__TMC_END__>";
	stig::x86_memory expected_mem {
		stig::x86_register::rip,
		std::nullopt,
		std::nullopt,
		0x2efd
	};
	stig::x86_immediate expected_immediate = { 0x01 };
	stig::x86_instruction expected = {
		0x110c,
		std::vector<uint8_t>{ 0xc6, 0x05, 0xfd, 0x2e, 0x00, 0x00, 0x01 },
		stig::x86_mnemonic::movb,
		std::vector<stig::x86_operand>{ expected_immediate, expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( movb_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}


TEST( UnitTest, ParseX86Instruction_Call ) {
	std::string call_instruction = "1102:	e8 29 ff ff ff       	call   1030 <__cxa_finalize@plt>";
	stig::x86_instruction expected = {
		0x1102,
		std::vector<uint8_t>{ 0xe8, 0x29, 0xff, 0xff, 0xff },
		stig::x86_mnemonic::call,
		std::vector<stig::x86_operand>{ stig::x86_address{ 0x1030 } }
	};
	auto parse_result = stig::parse_x86_instruction( call_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Cmpq ) {
	std::string cmpq_instruction = "10ee:	48 83 3d 02 2f 00 00 	cmpq   $0x0,0x2f02(%rip)        # 3ff8 <__cxa_finalize@GLIBC_2.2.5>";
	stig::x86_memory expected_mem{
		stig::x86_register::rip,
		std::nullopt,
		std::nullopt,
		0x2f02
	};
	stig::x86_instruction expected = {
		0x10ee,
		std::vector<uint8_t>{ 0x48, 0x83, 0x3d, 0x02, 0x2f, 0x00, 0x00 },
		stig::x86_mnemonic::cmpq,
		std::vector<stig::x86_operand>{ stig::x86_immediate{ 0x00 }, expected_mem }
	};
	auto parse_result = stig::parse_x86_instruction( cmpq_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Lea ) {
	std::string lea_instruction = "10a0:	48 8d 3d 69 2f 00 00 	lea    0x2f69(%rip),%rdi        # 4010 <__TMC_END__>";
	stig::x86_memory expected_mem{
		stig::x86_register::rip,
		std::nullopt,
		std::nullopt,
		0x2f69
	};
	stig::x86_instruction expected = {
		0x10a0,
		std::vector<uint8_t>{ 0x48, 0x8d, 0x3d, 0x69, 0x2f, 0x00, 0x00 },
		stig::x86_mnemonic::lea,
		std::vector<stig::x86_operand>{ expected_mem, stig::x86_register::rdi }
	};
	auto parse_result = stig::parse_x86_instruction( lea_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Sar ) {
	std::string sar_instruction = "10bf:	48 d1 fe             	sar    $1,%rsi";
	stig::x86_instruction expected = {
		0x10bf,
		std::vector<uint8_t>{ 0x48, 0xd1, 0xfe },
		stig::x86_mnemonic::sar,
		std::vector<stig::x86_operand>{ stig::x86_immediate{ 0x01 }, stig::x86_register::rsi }
	};
	auto parse_result = stig::parse_x86_instruction( sar_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Je ) {
	std::string je_instruction = "10c2:	74 14                	je     10d8 <register_tm_clones+0x38>";
	stig::x86_instruction expected = {
		0x10c2,
		std::vector<uint8_t>{ 0x74, 0x14 },
		stig::x86_mnemonic::je,
		std::vector<stig::x86_operand>{ stig::x86_address{ 0x10d8 } }
	};
	auto parse_result = stig::parse_x86_instruction( je_instruction );
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Cmpxchg ) {
	std::string cmpxchg = "4011d1: f0 0f b1 15 67 4a 0b lock cmpxchg %edx,0xb4a67(%rip) # 4b5c40 <lock>";
	stig::x86_memory mem{
		stig::x86_register::rip,
		std::nullopt,
		std::nullopt,
		0xb4a67
	};
	stig::x86_instruction expected = {
		0x4011d1,
		std::vector<uint8_t>{ 0xf0, 0x0f, 0xb1, 0x15, 0x67, 0x4a, 0x0b },
		stig::x86_mnemonic::cmpxchg,
		std::vector<stig::x86_operand>{ stig::x86_register::edx, mem }
	};
	auto parse_result = stig::parse_x86_instruction( cmpxchg );
	ASSERT_TRUE( parse_result ) << parse_result.error(); 
	auto& parsed_instruction = parse_result.value();
	EXPECT_EQ( parsed_instruction.instruction, expected );
}

TEST( UnitTest, ParseX86Instruction_Sub_Bytes ) {
	std::vector<uint8_t> bytes = { 0x48, 0x83, 0xec, 0x08 };
	auto res = stig::parse_x86_instruction( bytes );
	ASSERT_TRUE( res ) << res.error();
}
