#include <sip_parser/sip_parser.hpp>
#include <iostream>
#include <malloc.h>

// namespace

std::deque<std::string> sip_packets;

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

void Sip_Parser::parsing(char *packet_msg) {
	// PARSING
	len = strlen(packet_msg);
	// DELETE printf
	//printf("LEN: %d\n", len);
	msg = pjsip_parse_msg(pool, packet_msg, len, &err);

	// Найти заголовок Call-ID
    pjsip_hdr *call_id_hdr = (pjsip_hdr *)pjsip_msg_find_hdr(msg, PJSIP_H_CALL_ID, NULL);
  
    // Проверить, найден ли заголовок
    if (call_id_hdr != NULL) {
    	// Извлечь значение Call-ID
    	char call_id_value[30];
		pj_ssize_t len;
		len = pjsip_hdr_print_on(call_id_hdr, call_id_value, 30);
		char *p = call_id_value;
		p+=9;
		if (len > 0) std::cout << "CALL-ID: " << p << "\n";
      
    }
    
}

void Sip_Parser::read_in_file(const std::string& name) {
	// READ
	std::ofstream out;
	out.open(name, std::ios::app);

	char *buf = (char*)malloc(len);
	pjsip_msg_print( msg, buf, len);

	for (int i = 0; i < strlen(buf); ++i) {
		out << buf[i];
	}
	
	
	out.close();

}