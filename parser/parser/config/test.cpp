#include <gtest/gtest.h>
#include <iostream>
#include <config/config.hpp>

namespace {
TEST(config1, json_schema_1) {
  std::string path_json = "../../../config/config_test_1.json";
  std::string path_schema = "../../../config/json_schema.json";
  bool flag = 1;

  try {
		obj_config::Obj_Config& obj = obj_config::Obj_Config::Instance(path_json, path_schema);
    auto head_and_option = obj.get_headers_and_option();

    auto& headers = head_and_option->headers;
    for (auto& elem_vec : headers) {
      if(elem_vec.name != "Via:" && elem_vec.name != "From:" && elem_vec.name != "To:" && elem_vec.name != "Call-ID:" && elem_vec.name != "CSeq:" && elem_vec.name != "Contact:" && elem_vec.name != "Content-Type:" 
        && elem_vec.name != "Content-Length:") {
        flag = 0;
      }
    }

    EXPECT_EQ(flag, 1);
	} catch (const char* error_message) {
    FAIL() << error_message << "\n";
  }
  
}

TEST(config2, json_schema_2) {
  std::string path_json = "../../../config/config_test_2.json";
  std::string path_schema = "../../../config/json_schema.json";
  bool flag = 1;

  try {
		obj_config::Obj_Config& obj = obj_config::Obj_Config::Instance();
    obj.Change_Obj_Config(path_json, path_schema);
    auto head_and_option = obj.get_headers_and_option();

    auto& headers = head_and_option->headers;
    for (auto& elem_vec : headers) {
      if(elem_vec.name != "Via:" && elem_vec.name != "From:" && elem_vec.name != "To:" && elem_vec.name != "Call-ID:" && elem_vec.name != "CSeq:" && elem_vec.name != "Contact:" && elem_vec.name != "Content-Type:" 
        && elem_vec.name != "Content-Length:") {
        flag = 0;
      }
    }

    EXPECT_EQ(flag, 0);
	} catch (const char* error_message) {
    FAIL() << error_message << "\n";
  }  
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

