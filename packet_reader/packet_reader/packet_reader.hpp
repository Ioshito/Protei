#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <queue>
#include <fstream>
#include <memory>

namespace packet_reader {

class Packet_Reader {
	public:
		Packet_Reader(const std::string&);
		~Packet_Reader();
		void set_filter(const std::string&);
		void get_link_header_len(pcap_t*);
		void processing (int) const;
		static void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
		std::unique_ptr<std::string> get_packet_front() const;
		size_t get_size_deque() const;
		void read_in_file(const std::string&) const;
	private:
		static int linkhdrlen;
		pcap_t* handle;
		char errbuf[PCAP_ERRBUF_SIZE];
	        struct pcap_pkthdr header;
	    	const uint8_t *packet;
	    	struct bpf_program fp;      /* hold compiled program     */
		static std::queue<std::unique_ptr<std::string>> packets;
};
}
