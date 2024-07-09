#include <stdio.h>
#include <pjlib.h>
#include <pjsip.h>
#include <fstream>
#include <deque>
#include <pj/log.h>
#include <queue>
#include <memory>
#include <map>

#define SIZE_BUF 1000

// namespace
namespace sip_parser {

typedef std::string Call_ID;

struct Info_and_Sip_Packet {
	long sec;
	long usec;
	std::string ip;
	int port;
	pjsip_msg *msg;
};

struct Key_and_Sides {
	std::string ip;
	int port;
	std::vector<Info_and_Sip_Packet> a;
	std::vector<Info_and_Sip_Packet> b;
};

class Sip_Parser {
	public:
		Sip_Parser();
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