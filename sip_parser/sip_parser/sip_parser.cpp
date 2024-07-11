#include <sip_parser/sip_parser.hpp>
#include <iostream>
#include <malloc.h>

// namespace
namespace sip_parser {

int Info_and_Sip_Packet::flag = 1;

std::map<Call_ID, Key_and_Sides> Sip_Parser::sip_packets;

pjsip_endpoint * Sip_Parser::sip_endpt;

Info_and_Sip_Packet::Info_and_Sip_Packet(){}

Info_and_Sip_Packet::Info_and_Sip_Packet(pjsip_msg *msg) {
	copy = msg;
}

pjsip_msg* Info_and_Sip_Packet::get_msg() {
	return copy;
}
std::string Info_and_Sip_Packet::get_packet() {
	return packet_;
}


Sip_Parser::Sip_Parser() {
	// INIT
	status = pj_init();
	
	pj_caching_pool_init(&cp, NULL, 1024*1024);

	status = pjsip_endpt_create(&cp.factory, "uniquesipendpointname", &sip_endpt);

	pool = pj_pool_create(&cp.factory, "parser_pool", 4000, 4000, NULL);

	pj_list_init(&err);
}
Sip_Parser::~Sip_Parser() {
	pj_pool_release(pool);
	pjsip_endpt_destroy(sip_endpt);
	pj_shutdown();
}

void Sip_Parser::parsing(char *packet_msg, long sec, long usec, std::string& ip, int port) {
	// PARSING
	len = strlen(packet_msg);
	msg = pjsip_parse_msg(pool, packet_msg, len, &err);

	// Найти заголовок Call-ID
    pjsip_hdr *call_id_hdr = (pjsip_hdr *)pjsip_msg_find_hdr(msg, PJSIP_H_CALL_ID, NULL);
  
    // Проверить, найден ли заголовок
    if (call_id_hdr != NULL) {
    	// Извлечь значение Call-ID
    	char call_id_value[50];
		pj_ssize_t len = 0;
		len = pjsip_hdr_print_on(call_id_hdr, call_id_value, 50);
		Call_ID call_id = call_id_value;

		try {
		//Info_and_Sip_Packet buf_info (sec, usec, std::move(ip), port, msg, buf, cp);       
		Info_and_Sip_Packet buf_info(msg);               

		if (auto search = sip_packets.find(call_id); search == sip_packets.end()) {
			std::vector<Info_and_Sip_Packet> a, b;
			Key_and_Sides k_a_s {ip, port, std::move(a), std::move(b)};
			const auto [it, success] = sip_packets.insert(std::pair{call_id, std::move(k_a_s)});
		}

		if (auto search = sip_packets.find(call_id); search != sip_packets.end()) {
			//добавить условие по флагу стороны
			if (search->second.ip_ == ip && search->second.port_ == port) {
				search->second.a.push_back(std::move(buf_info));
			}
			else {
				search->second.b.push_back(std::move(buf_info));
			}
		}
		
		}
		catch (...) {
			std::cout << "ERROR";
		}
	}
	else {
		std::cout << "ERROR";
	}
}

void Sip_Parser::read_in_file(const std::string& name) {
	// READ
	std::ofstream out;
	out.open(name+".txt", std::ios::app);

	char *buf = (char*)malloc(SIZE_BUF);
	pjsip_msg_print( msg, buf, SIZE_BUF);

	for (int i = 0; i < strlen(buf); ++i) {
		out << buf[i];
	}
	free(buf);
	out.close();

}

void Sip_Parser::read_in_files(const std::string& name) {
	// READ
	std::ofstream out_a, out_b;
	out_a.open(name+"_a.txt");
	out_b.open(name+"_b.txt");

	for (const auto& [call_id, key_and_sides] : sip_packets) {
		for (auto elem : key_and_sides.a) {
			char *buf = (char*)malloc(SIZE_BUF);
			pjsip_msg_print(elem.get_msg(), buf, SIZE_BUF);                                                                 
			std::string buf_str = buf;
			out_a << buf_str; 
			free(buf);
		}
		for (auto elem : key_and_sides.b) {
			char *buf = (char*)malloc(SIZE_BUF);
			pjsip_msg_print(elem.get_msg(), buf, SIZE_BUF);                                                                 
			std::string buf_str = buf;
			out_b << buf_str; 
			free(buf);                                                                                   
		}
	}
	
	out_a.close();
	out_b.close();

}
}