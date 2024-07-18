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