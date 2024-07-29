#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <vector>
#include <variant>
#include <optional>

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

class Obj_Config
{
    public:
            static Obj_Config& Instance(std::string path = "") {
                static Obj_Config theSingleInstance(path);
                return theSingleInstance;
            }
            nlohmann::json* get_json();
            headers_and_option* get_headers_and_option();
            
    private:        
            Obj_Config(std::string&);
            Obj_Config(const Obj_Config&) = delete;
            Obj_Config& operator=(const Obj_Config&) = delete;
            nlohmann::json json_data_;
            headers_and_option* head_and_option;
};
} // namespace