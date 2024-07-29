#include <config/config.hpp>

namespace obj_config {

Obj_Config::Obj_Config(std::string& path) {
    std::cout << path << "\n";
    std::ifstream f(path);
    json_data_ = nlohmann::json::parse(f);
    
    std::vector<header> headers;

    auto first_level = json_data_.begin();
    auto second_level = (*first_level).begin();
    for (nlohmann::json::iterator obj = (*second_level).begin(); obj != (*second_level).end(); ++obj) {
        header p = {"", {}};
        for (auto elem = (*obj).begin(); elem != (*obj).end(); ++elem) {
            std::string key, value;
            elem.value().get_to(value);
            if (elem.key() == "name") p.name = value;
            if (elem.key() == "value") {
                p.value.emplace(value);
            }
        }
        headers.push_back(p);
    }

    second_level++;
    auto option_name_json = (*second_level).begin();
    bool flag;
    option_name_json.value().get_to(flag);
    option_name option_name = { flag };

    head_and_option = new headers_and_option { headers, option_name };
    // head_and_option->head = headers;
    // head_and_option->option = option_name;
}

nlohmann::json* Obj_Config::get_json() {
    return &json_data_;
}

headers_and_option* Obj_Config::get_headers_and_option() {
    return head_and_option;
}




} // namespace