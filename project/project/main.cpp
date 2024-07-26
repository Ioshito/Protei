#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>
#include <argparse/argparse.hpp>
#include <obj_config/obj_config.hpp>

int main(int argc, char **argv) {

	argparse::ArgumentParser program("app");
	program.add_argument("path_pcap").help("path_pcap to packets_pcap");
	program.add_argument("filter").help("filter to packet_reader");
	program.add_argument("reg_exp").help("regular_expression");
	program.add_argument("path_json").help("path_json to config");

	try {
  	  program.parse_args(argc, argv);
  	}
  	catch (const std::exception& err) {
  	  std::cerr << err.what() << std::endl;
  	  std::cerr << program;
  	  return 1;
  	}

	std::string path_pcap = program.get<std::string>("path_pcap");
	std::string filter = program.get<std::string>("filter");
	std::string reg_exp = program.get<std::string>("reg_exp");
	std::string path_json = program.get<std::string>("path_json");
	
	obj_config::Obj_Config& obj = obj_config::Obj_Config::Instance(path_json);

	if(argc < 3){ fprintf(stdout,"Usage: %s name_file filter\n",argv[0]); return 0;}

	packet_reader::Packet_Reader_Offline pr(path_pcap);
	pr.set_filter(filter);
    pr.processing(0);
	pr.read_in_file("packet_pcap.txt");
	
	sip_parser::Sip_Parser sp(&pr, reg_exp);

	sp.read_in_files("scenario");
	
    return 0;
}
