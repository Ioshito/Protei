#include <stdio.h>
#include <pjlib.h>
#include <pjsip.h>
#include <fstream>
#include <deque>
#include <pj/log.h>
#include <queue>
#include <memory>
#include <map>
#include <queue>
#include <packet_reader/packet_reader.hpp>
#define SIZE_BUF 1000

PJ_DEF(pj_ssize_t) pjsip_msg_print_user( const pjsip_msg *msg, char *buf, pj_size_t size);

// namespace
namespace sip_parser {

typedef std::string Call_ID;

class Info_and_Sip_Packet {
	public:
		//Info_and_Sip_Packet(long, long, std::string, int, pjsip_msg *, std::string, pj_caching_pool &);
		Info_and_Sip_Packet(pjsip_msg *);
		Info_and_Sip_Packet();
		//~Info_and_Sip_Packet();
		pjsip_msg* get_msg();
		std::string get_packet();
	private:
		pj_pool_t *msg_pool_;
		pj_pool_t *msg_pool_2;
		long sec_;
		long usec_;
		std::string ip_;
		int port_;
		pjsip_msg *copy;
		std::string packet_;
		static int flag;
};

struct Key_and_Sides {
	//public:
	//	Key_and_Sides(std::string, int);
	//	void push_back_a(Info_and_Sip_Packet);
	//	void push_back_b(Info_and_Sip_Packet);
	//private:
		std::string ip_;
		int port_;
		std::vector<Info_and_Sip_Packet> a;
		std::vector<Info_and_Sip_Packet> b;
};

class Sip_Parser {
	public:
		Sip_Parser(packet_reader::Packet_Reader_Interface *);
		~Sip_Parser();
		void read_in_file(const std::string&);
		void read_in_files(const std::string&);
		std::map<Call_ID, Key_and_Sides>* get_sip_packets();
		void clear_sip_packets();

	private:
		void parsing(char *, long, long, std::string&, int);
		
		packet_reader::Packet_Reader_Interface *pr_;
		int len;
		pjsip_msg *msg;
	    pj_size_t msgsize;
	    pj_status_t status;
		pj_caching_pool cp;
		static pjsip_endpoint *sip_endpt;
		pj_pool_t *pool;
		pjsip_parser_err_report err;
		static std::map<Call_ID, Key_and_Sides> sip_packets;
};

}