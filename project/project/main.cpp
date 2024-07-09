#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>

int main(int argc, char **argv) {

	bool need_time = false;

	if(argc < 3){ fprintf(stdout,"Usage: %s name_file filter\n",argv[0]); return 0;}

	packet_reader::Packet_Reader pr(argv[1]);
	pr.set_filter(argv[2]);
    	pr.processing(0);
	//pr.read_in_file("packet_pcap.txt");
	

	sip_parser::Sip_Parser sp;

    
	for (std::unique_ptr<packet_reader::Info_and_Packet> testmsg = pr.get_packet_front(); testmsg != nullptr; testmsg = pr.get_packet_front()) {
		//std::unique_ptr<packet_reader::Time_and_Packet> testmsg = pr.get_packet_front();
		sp.parsing(testmsg->packet.data(), testmsg->sec, testmsg->usec, testmsg->ip, testmsg->port);
		sp.read_in_file("packet_sip");
		testmsg.reset();
	}

	if (need_time) sp.read_in_files("packet_sip");
	else sp.read_in_files("packet_sip");
	

    	return 0;
}
