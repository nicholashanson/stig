#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, GetElfHeader ) {
	auto result = stig::get_elf_header( "../test/main" );
}