#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ParseElf64Shdr ) {
	auto hdr_result = stig::get_elf_header( "../test/main" );
	ASSERT_TRUE( hdr_result ) << hdr_result.error();
	std::ifstream file( "../test/main", std::ios::binary );
	auto shdr_result = stig::parse_elf64_shdr( file, hdr_result.value() ); 
	ASSERT_TRUE( shdr_result ) << shdr_result.error();
} 