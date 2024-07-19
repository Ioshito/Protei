#include <packet_reader/packet_reader.hpp>
#include <sip_parser/sip_parser.hpp>

int main(int argc, char **argv) {

	bool need_time = false;

	if(argc < 3){ fprintf(stdout,"Usage: %s name_file filter\n",argv[0]); return 0;}

	packet_reader::Packet_Reader_Offline pr(argv[1]);
	pr.set_filter(argv[2]);
    pr.processing(0);
	pr.read_in_file("packet_pcap.txt");
	
	sip_parser::Sip_Parser sp(&pr);

	if (need_time) sp.read_in_files("scenario");
	else sp.read_in_files("scenario");
	
    return 0;
}
