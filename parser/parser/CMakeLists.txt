set(target_name_lib sip_parser)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lpcap -g")

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
target_link_libraries(
	${target_name_lib}
	packet_reader
	config
)

option(TEST "Add a test_sip_parser" ON)

if (TEST) 
	set(target_name_test googletest_sip_parser)

	add_executable(
		${target_name_test}
		sip_parser/test.cpp
	)
	target_link_libraries(
		${target_name_test}
		sip_parser
		PkgConfig::pjproject
		config
		gtest
		gmock
	)

	include(GoogleTest)
	gtest_discover_tests(${target_name_test})
endif()

# packet_reader

set(target_name_lib packet_reader)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lpcap")

add_library(${target_name_lib} STATIC
        packet_reader/packet_reader.cpp
        packet_reader/packet_reader.hpp)

target_include_directories(
	${target_name_lib} 
	PUBLIC 
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

option(TEST "Add a test_packet_reader" ON)

if (TEST) 
	set(target_name_test googletest_packet_reader)

	add_executable(
		${target_name_test}
		packet_reader/test.cpp
	)
	target_link_libraries(
		${target_name_test}
		packet_reader
		gtest
	)

	include(GoogleTest)
	gtest_discover_tests(${target_name_test})
endif()

# config

set(target_name_lib config)

add_library(${target_name_lib} STATIC
        config/config.cpp
        config/config.hpp)

target_include_directories(
	${target_name_lib} 
	PUBLIC 
	"${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(
	${target_name_lib}
	nlohmann_json::nlohmann_json
)

option(TEST "Add a test_config" ON)

if (TEST) 
	set(target_name_test googletest_config)

	add_executable(
		${target_name_test}
		config/test.cpp
	)
	target_link_libraries(
		${target_name_test}
		config
		gtest
		gmock
	)

	include(GoogleTest)
	gtest_discover_tests(${target_name_test})
endif()