set(target_name_lib sip_parser)
set(target_name_test googletest_sip_parser)

find_package(PkgConfig REQUIRED)

set(ENV{PKG_CONFIG_PATH} "/home/ioshito/Protei/pjsip/test/lib/pkgconfig")
pkg_check_modules(pjproject REQUIRED IMPORTED_TARGET libpjproject)


add_library(${target_name_lib} STATIC
        sip_parser/sip_parser.cpp
        sip_parser/sip_parser.hpp)

target_include_directories(
	${target_name_lib} 
	PUBLIC 
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

add_executable(
	${target_name_test}
	sip_parser/test.cpp
)
target_link_libraries(
	${target_name_test}
	sip_parser
	PkgConfig::pjproject
	gtest
)

include(GoogleTest)
gtest_discover_tests(${target_name_test})
