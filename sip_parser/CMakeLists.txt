set(target_name_lib sip_parser)

add_library(${target_name_lib} STATIC
        sip_parser/sip_parser.cpp
        sip_parser/sip_parser.hpp)

target_include_directories(
	${target_name_lib} 
	PUBLIC 
	"${CMAKE_CURRENT_SOURCE_DIR}"
)
