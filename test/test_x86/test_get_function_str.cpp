#include <gtest/gtest.h>

#include <x86.hpp>

static std::string init_function = R"(0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    $0x8,%rsp
  401008:	48 c7 c0 00 00 00 00 	mov    $0x0,%rax
  40100f:	48 85 c0             	test   %rax,%rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   *%rax
  401016:	48 83 c4 08          	add    $0x8,%rsp
  40101a:	c3                   	ret
)";

TEST( UnitTest, GetFunctionStr ) {
	std::ifstream file( "../test/main_static.txt" );
	ASSERT_TRUE( file );
	auto result = stig::get_function_str( file, "_init" );
	ASSERT_TRUE( result );
	EXPECT_EQ( result.value(), init_function );
}