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

/*Info_and_Sip_Packet::Info_and_Sip_Packet(long sec, long usec, std::string ip, int port, pjsip_msg *msg, std::string packet, pj_caching_pool &cp)
	: sec_(sec), usec_(usec), ip_(ip), port_(port), packet_(packet) {
		std::string name = "msg_pool";
		//std::string name2= "msg_pool_2";
		msg_pool_ = pj_pool_create(&cp.factory, name.data(), 4096, 4096, NULL);
		//msg_pool_2 = pj_pool_create(&cp.factory, name2.data(), 4096, 4096, NULL);
		//if (flag == 1) 
			copy = pjsip_msg_clone(msg_pool_, msg);
		//else copy = pjsip_msg_clone(msg_pool_2, msg);
		if (!copy) {
	    	throw "ERROR";
		}
		++flag;
	}
*/

/*Info_and_Sip_Packet::~Info_and_Sip_Packet() {
	pj_pool_release(msg_pool_);
	pj_pool_release(msg_pool_2);
}
*/
pjsip_msg* Info_and_Sip_Packet::get_msg() {
	return copy;
}
std::string Info_and_Sip_Packet::get_packet() {
	return packet_;
}

/*
Key_and_Sides::Key_and_Sides(std::string ip, int port): ip_(ip), port_(port) {}

void Key_and_Sides::push_back_a(Info_and_Sip_Packet buf) {
	a.push_back(buf);
}

void Key_and_Sides::push_back_b(Info_and_Sip_Packet buf) {
	b.push_back(buf);
}
*/

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
/*
	std::cout << "TEEEEEEEST-----------------------------------------------------------\n";
	char *buf = (char*)malloc(len);
	pjsip_msg_print( msg, buf, len);

	for (int i = 0; i < strlen(buf); ++i) {
		std::cout << buf[i];
	}
	std::cout << "END_TEST______________________________________________________________\n";
	free(buf);
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
//		if (len > 0) std::cout << call_id << "; Length: " << call_id.length() << "\n";

		try {
		//Info_and_Sip_Packet buf_info (sec, usec, std::move(ip), port, msg, buf, cp);       
		Info_and_Sip_Packet buf_info(msg);               
/*     
		char *buf2 = (char*)malloc(SIZE_BUF);
		pjsip_msg_print( buf_info.get_msg(), buf2, SIZE_BUF);
		std::string buf_str = buf2;
		std::cout << "TWO TEST-----------------------------------\n" << buf << "END_TWO_TEST___________________________________\n";
		free(buf2);
*/
		if (auto search = sip_packets.find(call_id); search == sip_packets.end()) {
			std::vector<Info_and_Sip_Packet> a, b;
			//a.push_back(std::move(buf_info));
			Key_and_Sides k_a_s {ip, port, std::move(a), std::move(b)};
			const auto [it, success] = sip_packets.insert(std::pair{call_id, std::move(k_a_s)});
			//std::cout << "\n\n\n" << success << "\n\n\n";
		}

		if (auto search = sip_packets.find(call_id); search != sip_packets.end()) {
			//добавить условие по флагу стороны
			if (search->second.ip_ == ip && search->second.port_ == port) {
				search->second.a.push_back(std::move(buf_info));
				//std::cout << "\n\n\nWrite a\n\n\n";
			}
			else {
				//std::cout << "\n\n\nWrite b\n\n\n";
				search->second.b.push_back(std::move(buf_info));
			}
		}
		
		}
		catch (...) {
			std::cout << "ERROR";
		}
		for (const auto& [call_id, key_and_sides] : sip_packets) {
			for (auto elem : key_and_sides.a) {
				/*
				char *buf3 = (char*)malloc(SIZE_BUF);
				pjsip_msg_print(elem.get_msg(), buf3, SIZE_BUF);                                                                 
				std::string buf_str = buf3;
				std::cout << "THREE TEST-----------------------------------\n" << buf_str << "END_THREE_TEST___________________________________\n";
				free(buf3);
				*/
			}
      
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
			//std::cout << "Copy_pool: " << buf_str;
			free(buf);
		}
		for (auto elem : key_and_sides.b) {
			out_b << elem.get_packet();                                                                                     
		}
	}
	
	out_a.close();
	out_b.close();

}
}