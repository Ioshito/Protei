#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>

int main(int argc, char **argv) {

	bool need_time = false;

	if(argc < 3){ fprintf(stdout,"Usage: %s name_file filter [--flags]\n",argv[0]); return 0;}

	if(argc == 4) {
		std::string arg = argv[3];
		if (arg == "--need_time") need_time = true;
		else std::cout << "--flags is incorrect";
	}

	packet_reader::Packet_Reader pr(argv[1]);
	pr.set_filter(argv[2]);
    	pr.processing(0);
	//pr.read_in_file("file.txt");
	

	Sip_Parser sp;

    
	for (std::unique_ptr<packet_reader::Time_and_Packet> testmsg = pr.get_packet_front(); testmsg != nullptr; testmsg = pr.get_packet_front()) {
		//std::unique_ptr<packet_reader::Time_and_Packet> testmsg = pr.get_packet_front();
		sp.parsing(testmsg->packet.data());
		if (need_time) sp.read_in_file("packet_sip.txt", testmsg->sec, testmsg->usec);
		else sp.read_in_file("packet_sip.txt");
		testmsg.reset();
	}
	

    	return 0;
}
