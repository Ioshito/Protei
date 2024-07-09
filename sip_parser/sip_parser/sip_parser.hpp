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
	int flag; // side: 1 - server, 0 - client
	pjsip_msg *msg;
};

class Sip_Parser {
	public:
		Sip_Parser();
		void parsing(char *, long, long);
		void read_in_file(const std::string&);
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
		static std::map<Call_ID, std::pair<std::vector<Info_and_Sip_Packet>, std::vector<Info_and_Sip_Packet>>> sip_packets;
};

}