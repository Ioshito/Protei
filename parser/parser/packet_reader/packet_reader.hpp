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

struct Info_and_Packet {
	long sec;
	long usec;
	std::string ip;
	int port;
	std::string packet;
};

class Packet_Reader_Interface {
	public:
		virtual ~Packet_Reader_Interface() = default; 
		virtual void set_filter(const std::string&) = 0;
		virtual void processing (int) = 0;
		virtual void read_in_file(const std::string&) = 0;
		virtual Info_and_Packet* get_packet(size_t) = 0;
		virtual size_t get_size() const = 0;																// Вернуть const
};

class Packet_Reader_Offline : public Packet_Reader_Interface {
	public:
		Packet_Reader_Offline(const std::string&);
		Packet_Reader_Offline(const std::string&, const std::string&);
		~Packet_Reader_Offline();
		void set_filter(const std::string&) override;
		void get_link_header_len(pcap_t*);
		void processing (int) override;
		static void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
		Info_and_Packet* get_packet(size_t) override;
		size_t get_size() const override;
		void read_in_file(const std::string&) override;

	private:
		static int linkhdrlen;
		pcap_t* pcap;
		char errbuf[PCAP_ERRBUF_SIZE];
	    struct pcap_pkthdr header;
	    const uint8_t *packet;
	    struct bpf_program fp;      /* hold compiled program     */
		static std::vector<std::unique_ptr<Info_and_Packet>> packets;
};
}
