cmake_minimum_required(VERSION 3.22)
project(
	project
	VERSION 1.0
	LANGUAGES CXX
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
#set(CMAKE_VERBOSE_MAKEFILE true)

add_subdirectory(packet_reader)
add_subdirectory(sip_parser)
add_subdirectory(project)
