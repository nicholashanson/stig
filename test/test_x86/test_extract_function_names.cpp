#include <gtest/gtest.h>

#include <x86.hpp>

TEST( UnitTest, ExtractFunctionNames ) {
	auto res = stig::extract_function_names( "../test/main_static.txt" );
	ASSERT_TRUE( res ) << res.error();
	for ( auto& str : res.value() ) {
		auto res = stig::extract_function( "../test/main_static.txt", str );
		ASSERT_TRUE( res ) << str << ": " << res.error();
	}
}