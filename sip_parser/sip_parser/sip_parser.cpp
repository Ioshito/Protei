#include <sip_parser/sip_parser.hpp>
#include <iostream>
#include <malloc.h>

// namespace
namespace sip_parser {

std::map<Call_ID, Key_and_Sides> Sip_Parser::sip_packets;

pjsip_endpoint * Sip_Parser::sip_endpt;

Sip_Parser::Sip_Parser() {
	// INIT
	status = pj_init();

	status = pjlib_util_init();
	
	pj_caching_pool_init(&cp, NULL, 1024*1024);

	status = pjsip_endpt_create(&cp.factory, "uniquesipendpointname", &sip_endpt);

	pool = pj_pool_create(&cp.factory, "parser_pool", 4000, 4000, NULL);
	
	pj_list_init(&err);
}

void Sip_Parser::parsing(char *packet_msg, long sec, long usec, std::string& ip, int port) {
	// PARSING
	len = strlen(packet_msg);
	// DELETE printf
	//printf("LEN: %d\n", len);
	msg = pjsip_parse_msg(pool, packet_msg, len, &err);

/*
	std::cout << "TEEEEEEEST-----------------------------------------------------------\n";
	char *buf = (char*)malloc(len);
	pjsip_msg_print( msg, buf, len);

	for (int i = 0; i < strlen(buf); ++i) {
		std::cout << buf[i];
	}
	std::cout << "END_TEST______________________________________________________________\n";
*/
	// Найти заголовок Call-ID
    pjsip_hdr *call_id_hdr = (pjsip_hdr *)pjsip_msg_find_hdr(msg, PJSIP_H_CALL_ID, NULL);
  
    // Проверить, найден ли заголовок
    if (call_id_hdr != NULL) {
    	// Извлечь значение Call-ID
    	char call_id_value[50];
		pj_ssize_t len = 0;
		len = pjsip_hdr_print_on(call_id_hdr, call_id_value, 50);
		Call_ID call_id = call_id_value;
		if (len > 0) std::cout << call_id << "; Length: " << call_id.length() << "\n";

		Info_and_Sip_Packet buf_info {sec, usec, std::move(ip), port, *msg};
		if (auto search = sip_packets.find(call_id); search != sip_packets.end()) {
			//добавить условие по флагу стороны
			if (search->second.ip == ip && search->second.port == port) {
				search->second.a.push_back(std::move(buf_info));
			}
			else {
				search->second.b.push_back(std::move(buf_info));
			}
		}
        else {
			std::vector<Info_and_Sip_Packet> a, b;
			// Добавить условие по флагу стороны
			a.push_back(std::move(buf_info));
			sip_packets.insert({call_id, {ip, port, std::move(a), std::move(b)}});
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

	char *buf = (char*)malloc(len);
	pjsip_msg_print( msg, buf, len);

	for (int i = 0; i < strlen(buf); ++i) {
		out << buf[i];
	}
	
	out.close();

}

void Sip_Parser::read_in_files(const std::string& name) {
	// READ
	std::ofstream out_a, out_b;
	out_a.open(name+"_a.txt", std::ios::app);
	out_b.open(name+"_b.txt", std::ios::app);

	char *buf = (char*)malloc(SIZE_BUF);

	for (const auto& [call_id, key_and_sides] : sip_packets) {
		for (auto elem : key_and_sides.a) {
			auto mess = elem.msg;
			//std::cout << "ABBA "<< msg.line.req.method.name.ptr;
			pjsip_msg_print(&mess, buf, SIZE_BUF);
			for (int i = 0; i < strlen(buf); ++i) {
				out_a << buf[i];
				std::cout << buf[i];
			}
		}
		for (auto elem : key_and_sides.b) {
			auto mess = elem.msg;
			pjsip_msg_print(&mess, buf, SIZE_BUF);
			for (int i = 0; i < strlen(buf); ++i)
				out_b << buf[i];
		}
	}
	
	out_a.close();
	out_b.close();

}
}