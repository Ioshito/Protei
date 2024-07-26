#include <obj_config/obj_config.hpp>


namespace obj_config {

Obj_Config::Obj_Config(std::string& path) {
    std::cout << path << "\n";
    std::ifstream f(path);
    json_data_ = nlohmann::json::parse(f);
}

nlohmann::json* Obj_Config::get_json() {
    return &json_data_;
}



} // namespace