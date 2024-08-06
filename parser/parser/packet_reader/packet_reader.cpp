#include "packet_reader.hpp"

namespace packet_reader{

long buf_sec = 0;
long buf_usec = 0;
int flag = 1;

int Packet_Reader_Offline::linkhdrlen = 0;

//std::deque<std::unique_ptr<std::string>> Packet_Reader_Offline::packets;
std::vector<std::unique_ptr<Info_and_Packet>> Packet_Reader_Offline::packets;

Packet_Reader_Offline::Packet_Reader_Offline(const std::string& name) {
	pcap = pcap_open_offline(name.c_str(), errbuf);
	if (pcap == nullptr) throw "Could not open file " + name + ": " + errbuf;
	get_link_header_len(pcap);
}
Packet_Reader_Offline::~Packet_Reader_Offline(){
	pcap_close(pcap);
}
void Packet_Reader_Offline::set_filter(const std::string& filter) {
	/* Lets try and compile the program.. non-optimized */
	if(pcap_compile(pcap, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) std::cout << "Error calling pcap_compile\n";

	/* set the compiled program as the filter */
	if(pcap_setfilter(pcap,&fp) == -1) std::cout << "Error setting filter\n";
}
void Packet_Reader_Offline::get_link_header_len(pcap_t* pcap)
{
    	int linktype;
 
    	// Determine the datalink layer type.
    	if ((linktype = pcap_datalink(pcap)) == PCAP_ERROR) {
		printf("pcap_datalink(): %s\n", pcap_geterr(pcap));
		return;
   	}
 
    	// Set the datalink layer header size.
    	switch (linktype)
    	{
	case DLT_LINUX_SLL:
		linkhdrlen = 16;
		break;

    	case DLT_NULL:
		linkhdrlen = 4;
		break;
 
    	case DLT_EN10MB:
		linkhdrlen = 14;
		break;
 
    	case DLT_SLIP:
    	case DLT_PPP:
		linkhdrlen = 24;
		break;
 
    	default:
		printf("Unsupported datalink (%d)\n", linktype);
		linkhdrlen = 0;
    	}
}
void Packet_Reader_Offline::processing (int count) {
	if (pcap_loop(pcap, count, packet_handler, (u_char*)NULL) == PCAP_ERROR)
		std::cout << "pcap_loop failed: " << pcap_geterr(pcap) << "\n";
}
void Packet_Reader_Offline::packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
	if (flag) {
		buf_sec = packethdr->ts.tv_sec;
		buf_usec = packethdr->ts.tv_usec;
		flag = 0;
	}

	/* header->ts содержит время прибытия пакета */
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* Преобразуем timestamp в локальное время */
	local_tv_sec = packethdr->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);


	/* Выводим время прибытия пакета */
	
	//printf("Время прибытия пакета: %s.%06ld\n", timestr, packethdr->ts.tv_usec);
	//printf("A: %07ld; B: %07ld\n", packethdr->ts.tv_sec, packethdr->ts.tv_usec);
	long result = packethdr->ts.tv_sec*1000000 - buf_sec*1000000 + packethdr->ts.tv_usec - buf_usec;
	//printf("Разница: %d.%06ld\n", result/1000000, result%1000000);
	

	std::stringstream buffer;
	struct ip* iphdr;
	struct icmp* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	char iphdrInfo[256];
	char srcip[256];
	char dstip[256];
	size_t packetptr_len = packethdr->len;
	 
	// Skip the datalink layer header and get the IP header fields.
	packetptr += linkhdrlen;
	packetptr_len -= linkhdrlen;
	iphdr = (struct ip*)packetptr;
	strcpy(srcip, inet_ntoa(iphdr->ip_src));
	strcpy(dstip, inet_ntoa(iphdr->ip_dst));
	sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
	ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
	4*iphdr->ip_hl, ntohs(iphdr->ip_len));
	 
	// Advance to the transport layer header then parse and display
	// the fields based on the type of hearder: tcp, udp or icmp.
	packetptr += 4*iphdr->ip_hl;
	packetptr_len -= 4*iphdr->ip_hl;
	switch (iphdr->ip_p)
	{
	case IPPROTO_TCP:
		tcphdr = (struct tcphdr*)packetptr;
		/*printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
		       dstip, ntohs(tcphdr->th_dport));
		printf("%s\n", iphdrInfo);
		printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
		       (tcphdr->th_flags & TH_URG ? 'U' : '*'),
		       (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
		       (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
		       (tcphdr->th_flags & TH_RST ? 'R' : '*'),
		       (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
		       (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
		       ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
		       ntohs(tcphdr->th_win), 4*tcphdr->th_off);
		printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
		*/
		packetptr += sizeof(tcphdr);
		packetptr_len -= sizeof(tcphdr);
		break;
	 
	case IPPROTO_UDP:
		udphdr = (struct udphdr*)packetptr;
		//printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
		       //dstip, ntohs(udphdr->uh_dport));
		//printf("%s\n", iphdrInfo);
		    //printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
		
		packetptr += sizeof(udphdr);
		packetptr_len -= sizeof(udphdr);
		break;
	 
	case IPPROTO_ICMP:
		icmphdr = (struct icmp*)packetptr;
		/*printf("ICMP %s -> %s\n", srcip, dstip);
		printf("%s\n", iphdrInfo);
		printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
		       ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
		    printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
		*/
		packetptr += sizeof(icmphdr);
		packetptr_len -= sizeof(icmphdr);
		break;
	}
	
	for (int i = 0; i < packetptr_len; ++i) {
		buffer << packetptr[i];
	}
	std::unique_ptr<Info_and_Packet> pStr(new Info_and_Packet({result/1000000, result%1000000, srcip, ntohs(udphdr->uh_sport), buffer.str()}));
	
	packets.push_back(std::move(pStr));
	buffer.str("");
}
Info_and_Packet* Packet_Reader_Offline::get_packet(size_t it){
	Info_and_Packet* value;
	value = packets[it].get();
	return value;
}
size_t Packet_Reader_Offline::get_size() const{
	return packets.size();
}
void Packet_Reader_Offline::read_in_file(const std::string& name) {
	std::ofstream out;
	out.open(name);
	for (int it = 0; it != get_size(); ++it) {
		packet_reader::Info_and_Packet* testmsg = get_packet(it); 
		out << testmsg->packet;
	}
	out.close();
}
} // namespace

