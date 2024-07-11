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
#define SIZE_BUF 1000

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
		Sip_Parser();
		~Sip_Parser();
		void parsing(char *, long, long, std::string&, int);
		void read_in_file(const std::string&);
		void read_in_files(const std::string&);
		char *packet_msg;

	private:
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