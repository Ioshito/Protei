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

#define SIZE_BUF 1000

PJ_DEF(pj_ssize_t) pjsip_msg_print_user( const pjsip_msg *msg, char *buf, pj_size_t size, std::string&);

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
		Sip_Parser(packet_reader::Packet_Reader_Interface *, std::string&);
		~Sip_Parser();
		void read_in_files(const std::string&);
		std::map<Call_ID, Key_and_Sides>* get_sip_packets();
		void clear_sip_packets();

	private:
		void parsing(char *, long, long, std::string&, int);
		void read_in_file(std::ofstream&, const std::vector<std::variant<Info_and_Sip_Packet, receive_type_msg>>&);
		
		std::string& reg_exp_;
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