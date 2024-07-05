#include <stdio.h>
#include <pjlib.h>
#include <pjsip.h>
#include <fstream>
#include <deque>
#include <pj/log.h>

#define SIZE_BUF 1000

// namespace

class Sip_Parser {
	public:
		Sip_Parser();
		void parsing(char *);
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
		static std::deque<std::string> sip_packets;
};
