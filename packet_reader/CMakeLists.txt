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
