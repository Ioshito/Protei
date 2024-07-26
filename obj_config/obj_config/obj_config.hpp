#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

namespace obj_config {
class Obj_Config
{
    public:
            static Obj_Config& Instance(std::string path = "") {
                static Obj_Config theSingleInstance(path);
                return theSingleInstance;
            }
            nlohmann::json* get_json();
            
    private:        
            Obj_Config(std::string&);
            Obj_Config(const Obj_Config&) = delete;
            Obj_Config& operator=(const Obj_Config&) = delete;
            nlohmann::json json_data_;
};
} // namespace