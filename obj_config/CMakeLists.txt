set(target_name_lib obj_config)

add_library(${target_name_lib} STATIC
        obj_config/obj_config.cpp
        obj_config/obj_config.hpp)

target_include_directories(
	${target_name_lib} 
	PUBLIC 
	"${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(
	${target_name_lib}
	nlohmann_json::nlohmann_json
)

option(TEST "Add a test_obj_config" ON)

if (TEST) 
	set(target_name_test googletest_obj_config)

	add_executable(
		${target_name_test}
		obj_config/test.cpp
	)
	target_link_libraries(
		${target_name_test}
		obj_config
		gtest
		gmock
	)

	include(GoogleTest)
	gtest_discover_tests(${target_name_test})
endif()