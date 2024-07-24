set(target_name app)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")

#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/home/ioshito/Protei/pjsip/pjproject/pjlib/lib -L/home/ioshito/Protei/pjsip/pjproject/pjlib-util/lib -L/home/ioshito/Protei/pjsip/pjproject/pjnath/lib -L/home/ioshito/Protei/pjsip/pjproject/pjmedia/lib -L/home/ioshito/Protei/pjsip/pjproject/pjsip/lib -L/home/ioshito/Protei/pjsip/pjproject/third_party/lib        -lpjsua2-x86_64-unknown-linux-gnu -lstdc++ -lpjsua-x86_64-unknown-linux-gnu -lpjsip-ua-x86_64-unknown-linux-gnu -lpjsip-simple-x86_64-unknown-linux-gnu -lpjsip-x86_64-unknown-linux-gnu -lpjmedia-codec-x86_64-unknown-linux-gnu -lpjmedia-videodev-x86_64-unknown-linux-gnu -lpjmedia-audiodev-x86_64-unknown-linux-gnu -lpjmedia-x86_64-unknown-linux-gnu -lpjnath-x86_64-unknown-linux-gnu -lpjlib-util-x86_64-unknown-linux-gnu -lsrtp-x86_64-unknown-linux-gnu -lresample-x86_64-unknown-linux-gnu -lgsmcodec-x86_64-unknown-linux-gnu -lspeex-x86_64-unknown-linux-gnu -lilbccodec-x86_64-unknown-linux-gnu -lg7221codec-x86_64-unknown-linux-gnu -lyuv-x86_64-unknown-linux-gnu -lwebrtc-x86_64-unknown-linux-gnu  -lpj-x86_64-unknown-linux-gnu -lm -lrt -lpthread -lpcap")
#set( CMAKE_VERBOSE_MAKEFILE on )

find_package(PkgConfig REQUIRED)

set(ENV{PKG_CONFIG_PATH} "/home/ioshito/Protei/pjsip/test/lib/pkgconfig")
pkg_check_modules(pjproject REQUIRED IMPORTED_TARGET libpjproject)

add_executable(${target_name})

target_sources(
	${target_name}
	PRIVATE
	project/main.cpp
)


target_link_libraries(
	${target_name}
#	PRIVATE
#	PUBLIC
	PkgConfig::pjproject
#	${pjproject_LIBRARIES}
	packet_reader
	sip_parser
	-lpcap
	argparse
)

#target_include_directories(${target_name} PUBLIC ${pjproject_INCLUDE_DIRS})
#target_compile_options(${target_name} PUBLIC ${pjproject_CFLAGS_OTHER})