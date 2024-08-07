#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <vector>
#include <variant>
#include <optional>
#include <nlohmann/json-schema.hpp>

namespace obj_config {

struct header {
	std::string name;
	std::optional<std::string> value;
};

struct option_name {
    bool flag;
};

struct headers_and_option {
    std::vector<header> headers;
    option_name option;
};

class Obj_Config {
    public:
            Obj_Config& operator=(Obj_Config &&) = default;
            static Obj_Config& Instance(std::string path_config = "", std::string path_schema = "") {
                try {
                    static Obj_Config theSingleInstance(path_config, path_schema);
                    return theSingleInstance;
                } catch (const char* error_message) {
                    std::cerr << error_message << "\n";
                    throw "Error Instance";
                }
            }
            nlohmann::json* get_json();
            headers_and_option* get_headers_and_option();
            void change_json_data(std::string&);
            void Change_Obj_Config(std::string path_config = "", std::string path_schema = "") {
                Instance() = Obj_Config(path_config, path_schema);
            }
            
    protected:
            Obj_Config(std::string&, std::string&);
            Obj_Config(const Obj_Config&) = delete;
            Obj_Config& operator=(const Obj_Config&) = delete;
            nlohmann::json json_data_;
            nlohmann::json json_schema_;
            nlohmann::json_schema::json_validator json_validator_;
            headers_and_option* head_and_option;
};
} // namespace