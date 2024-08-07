#include <config/config.hpp>

namespace obj_config {

Obj_Config::Obj_Config(std::string& path_config, std::string& path_schema) {
    try {
        std::ifstream f_conf(path_config);
        std::ifstream f_sch(path_schema);
        json_schema_ = nlohmann::json::parse(f_sch);

        json_validator_.set_root_schema(json_schema_);
        json_data_ = nlohmann::json::parse(f_conf);
        class custom_error_handler : public nlohmann::json_schema::basic_error_handler
        {
        	void error(const nlohmann::json::json_pointer &ptr, const nlohmann::json &instance, const std::string &message) override
        	{
        		nlohmann::json_schema::basic_error_handler::error(ptr, instance, message);
        		std::cerr << "ERROR: '" << ptr << "' - '" << instance << "': " << message << "\n";
        	}
        };
        custom_error_handler err;
        json_validator_.validate(json_data_, err);
        if (err) {
            throw "Error validate";
        }

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
    } catch (const std::exception &e) {
        std::cerr << "Validation of schema failed, here is why: " << e.what() << "\n";
        throw "Error Obj_Config";
    } catch (const char* error_message) {
        std::cerr << error_message << "\n";
        throw "Error Obj_Config";
    }
    
}

nlohmann::json* Obj_Config::get_json() {
    return &json_data_;
}

headers_and_option* Obj_Config::get_headers_and_option() {
    return head_and_option;
}

void Obj_Config::change_json_data(std::string& data) {
    try {
        json_data_ = nlohmann::json::parse(data);
        class custom_error_handler : public nlohmann::json_schema::basic_error_handler
        {
        	void error(const nlohmann::json::json_pointer &ptr, const nlohmann::json &instance, const std::string &message) override
        	{
        		nlohmann::json_schema::basic_error_handler::error(ptr, instance, message);
        		std::cerr << "ERROR: '" << ptr << "' - '" << instance << "': " << message << "\n";
        	}
        };
        custom_error_handler err;
        json_validator_.validate(json_data_, err);
        if (err) {
            throw "Error validate";
        }

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
        
    } catch (const char* error_message) {
        std::cerr << error_message << "\n";
        throw "Error Obj_Config";
    }
}

} // namespace