#include <stdio.h>
#include <pjlib.h>
#include <pjsip.h>
#include <fstream>
#include <deque>
#include <pj/log.h>
#include <queue>
#include <memory>
#include <map>
#include <unordered_map>
#include <queue>
#include <packet_reader/packet_reader.hpp>
#include <variant>
#include <iostream>
#include <malloc.h>
#include <regex>
#include <config/config.hpp>
#include <unordered_set>

#define SIZE_BUF 1000


// namespace
namespace sip_parser {

typedef std::string Call_ID;

enum type_msg {
	ERROR,
	INVITE,
	ACK,
	BYE,
	TRYING,
	RINGING,
	OK	
};

struct receive_type_msg {
	type_msg t_msg;
};

class Info_and_Sip_Packet {
	public:
		Info_and_Sip_Packet(long, long, std::string, int, pjsip_msg *, type_msg);
		Info_and_Sip_Packet(pjsip_msg *);
		Info_and_Sip_Packet();
		//~Info_and_Sip_Packet();
		pjsip_msg* get_msg();
		type_msg get_type_msg();
		long get_sec();
	private:
		long sec_;
		long usec_;
		std::string ip_;
		int port_;
		pjsip_msg *copy;
		type_msg t_msg_;
};


struct Key_and_Sides {
	//public:
	//	Key_and_Sides(std::string, int);
	//	void push_back_a(Info_and_Sip_Packet);
	//	void push_back_b(Info_and_Sip_Packet);
	//private:
		std::string ip_;
		int port_;
		std::vector<std::variant<Info_and_Sip_Packet, receive_type_msg>> a;
		std::vector<std::variant<Info_and_Sip_Packet, receive_type_msg>> b;
};

class Sip_Parser {
	public:
		Sip_Parser(packet_reader::Packet_Reader_Interface *);
		~Sip_Parser();
		void read_in_files(const std::string&);
		std::map<Call_ID, Key_and_Sides>* get_sip_packets();
		void clear_sip_packets();

		PJ_DEF(pj_ssize_t) pjsip_msg_print_user( const pjsip_msg *msg, char *buf, pj_size_t size);


	private:
		void parsing(char *, long, long, std::string&, int);
		void read_in_file(std::string&, const std::vector<std::variant<Info_and_Sip_Packet, receive_type_msg>>&);
		
		PJ_DEF(pj_status_t) pjsua_sip_url_user(const char *c_url);
		std::string template_selection(std::string& header_name, std::string& header, bool flag, std::string method);

		packet_reader::Packet_Reader_Interface *pr_;
		static std::map<Call_ID, Key_and_Sides> sip_packets;

		std::string method;
		std::unordered_set<std::string> global_variables;

	    pj_status_t status;
		pj_caching_pool cp;
		static pjsip_endpoint *sip_endpt;
		pj_pool_t *pool;
		pjsip_parser_err_report err;
};

}