#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>
#include <argparse/argparse.hpp>

int main(int argc, char **argv) {

	argparse::ArgumentParser program("app");
	program.add_argument("path").help("path to pcap_test");
	program.add_argument("filter").help("filter to packet_reader");
	program.add_argument("reg_exp").help("regular_expression");

	try {
  	  program.parse_args(argc, argv);
  	}
  	catch (const std::exception& err) {
  	  std::cerr << err.what() << std::endl;
  	  std::cerr << program;
  	  return 1;
  	}

	std::string name = program.get<std::string>("path");
	std::string filter = program.get<std::string>("filter");
	std::string reg_exp = program.get<std::string>("reg_exp");
	//std::cout << name << "\n" << reg_exp << "\n";

	if(argc < 3){ fprintf(stdout,"Usage: %s name_file filter\n",argv[0]); return 0;}

	packet_reader::Packet_Reader_Offline pr(name);
	pr.set_filter(filter);
    pr.processing(0);
	pr.read_in_file("packet_pcap.txt");
	
	sip_parser::Sip_Parser sp(&pr, reg_exp);

	sp.read_in_files("scenario");
	
    return 0;
}
