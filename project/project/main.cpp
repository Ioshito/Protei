#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>
#include <argparse/argparse.hpp>
#include <config/config.hpp>

int main(int argc, char **argv) {
	std::string path_pcap, filter, path_json, path_schema;

	argparse::ArgumentParser program("app");
	program.add_argument("--path_pcap").help("path_pcap to packets_pcap").required().store_into(path_pcap);
	program.add_argument("--filter").help("filter to packet_reader").default_value(std::string("-")).store_into(filter);
	program.add_argument("--path_json").help("path_json to config").required().store_into(path_json);
	program.add_argument("--path_schema").help("path_schema to config").required().store_into(path_schema);

	try {
  	  program.parse_args(argc, argv);
  	}
  	catch (const std::exception& err) {
  	  std::cerr << err.what() << std::endl;
  	  std::cerr << program;
  	  return -1;
  	}
	
	try {
		obj_config::Obj_Config& obj = obj_config::Obj_Config::Instance(path_json, path_schema);
	} catch (const char* error_message) {
        std::cerr << error_message << "\n";
		return -1;
    }

	try {
		packet_reader::Packet_Reader_Offline pro(path_pcap, filter);
		pro.processing(0);
		pro.read_in_file("packet_pcap.txt");
		
		sip_parser::Sip_Parser sp(&pro);
	
		sp.read_in_files("scenario");
	}
	catch (const char* error_message) {
		std::cout << error_message << "\n";
	}
	
    return 0;
}
