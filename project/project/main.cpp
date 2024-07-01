#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>

int main(int argc, char **argv) {

	if(argc != 3){ fprintf(stdout,"Usage: %s name_file filter\n",argv[0]); return 0;}

	packet_reader::Packet_Reader pr(argv[1]);
	pr.set_filter(argv[2]);
    	pr.processing(0);
	//pr.read_in_file("file.txt");
	

	Sip_Parser sp;

    
	for (std::unique_ptr<std::string> testmsg = pr.get_packet_front(); testmsg != nullptr; testmsg = pr.get_packet_front()) {

		sp.parsing((*testmsg).data());
		sp.read_in_file("packet_sip.txt");
		testmsg.reset();
	}
	

    	return 0;
}
