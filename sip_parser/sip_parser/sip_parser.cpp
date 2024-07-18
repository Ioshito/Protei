#include <sip_parser/sip_parser.hpp>
#include <iostream>
#include <malloc.h>


int print_media_type_user(char *buf, unsigned len,
                            const pjsip_media_type *media)
{
    char *p = buf;
    pj_ssize_t printed;
    const pjsip_parser_const_t *pc;

    pj_memcpy(p, media->type.ptr, media->type.slen);
    p += media->type.slen;
    *p++ = '/';
    pj_memcpy(p, media->subtype.ptr, media->subtype.slen);
    p += media->subtype.slen;

    pc = pjsip_parser_const();
    printed = pjsip_param_print_on(&media->param, p, buf+len-p,
                                   &pc->pjsip_TOKEN_SPEC,
                                   &pc->pjsip_TOKEN_SPEC, ';');
    if (printed < 0)
        return -1;

    p += printed;

    return (int)(p-buf);
}


PJ_DEF(pj_ssize_t) pjsip_msg_print_user( const pjsip_msg *msg, 
                                    char *buf, pj_size_t size)
{
    char *p=buf, *end=buf+size;
    pj_ssize_t len;
    pjsip_hdr *hdr;
    pj_str_t clen_hdr =  { "Content-Length: ", 16};

    if (pjsip_cfg()->endpt.use_compact_form) {
        clen_hdr.ptr = "l: ";
        clen_hdr.slen = 3;
    }

    /* Get a wild guess on how many bytes are typically needed.
     * We'll check this later in detail, but this serves as a quick check.
     */
    if (size < 256)
        return -1;

    /* Print request line or status line depending on message type */
    if (msg->type == PJSIP_REQUEST_MSG) {
        pjsip_uri *uri;

        /* Add method. */
        len = msg->line.req.method.name.slen;
        pj_memcpy(p, msg->line.req.method.name.ptr, len);
        p += len;
        *p++ = ' ';

        /* Add URI */
        uri = (pjsip_uri*) pjsip_uri_get_uri(msg->line.req.uri);
        len = pjsip_uri_print( PJSIP_URI_IN_REQ_URI, uri, p, end-p);
        if (len < 1)
            return -1;
        p += len;

        /* Add ' SIP/2.0' */
        if (end-p < 16)
            return -1;
        pj_memcpy(p, " SIP/2.0\r\n", 10);
        p += 10;

    } else {

        /* Add 'SIP/2.0 ' */
        pj_memcpy(p, "SIP/2.0 ", 8);
        p += 8;

        /* Add status code. */
        len = pj_utoa(msg->line.status.code, p);
        p += len;
        *p++ = ' ';

        /* Add reason text. */
        len = msg->line.status.reason.slen;
        pj_memcpy(p, msg->line.status.reason.ptr, len );
        p += len;

        /* Add newline. */
        *p++ = '\r';
        *p++ = '\n';
    }

    /* Print each of the headers. */
    for (hdr=msg->hdr.next; hdr!=&msg->hdr; hdr=hdr->next) {
        len = pjsip_hdr_print_on(hdr, p, end-p);
        if (len < 0) {
           if (len == -2) {
               PJ_LOG(5, ("sip_msg", "Header with no vptr encountered!! "\
                          "Current buffer: %.*s", (int)(p-buf), buf));
           }
           return len;
        }

        if (len > 0) {
            p += len;
            if (p+3 >= end)
                return -1;

            *p++ = '\r';
            *p++ = '\n';
        }
    }

    /* Process message body. */
    if (msg->body) {
        enum { CLEN_SPACE = 5 };
        char *clen_pos = NULL;
        
        /* Add blank newline. */
        *p++ = '\r';
        *p++ = '\n';

        /* Print the message body itself. */
        len = (*msg->body->print_body)(msg->body, p, end-p);
        if (len < 0) {
            return -1;
        }
        p += len;

        /* Now that we have the length of the body, print this to the
         * Content-Length header.
         */
        /*if (clen_pos) {
            char tmp[16];
            len = pj_utoa((unsigned long)len, tmp);
            if (len > CLEN_SPACE) len = CLEN_SPACE;
            pj_memcpy(clen_pos+CLEN_SPACE-len, tmp, len);
        }
		*/
    }

    *p = '\0';
    return p-buf;
}

// namespace
namespace sip_parser {

int Info_and_Sip_Packet::flag = 1;

std::map<Call_ID, Key_and_Sides> Sip_Parser::sip_packets;

std::unordered_map<std::string, receive> string_in_receive {{"INVITE", INVITE}, {"ACK", ACK}, {"BYE", BYE}, {"Trying", TRYING}, {"Ringing", RINGING}, {"OK", OK}};

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



Sip_Parser::Sip_Parser(packet_reader::Packet_Reader_Interface *pr): pr_(pr) {
	// INIT
	status = pj_init();
	
	pj_caching_pool_init(&cp, NULL, 1024*1024);

	status = pjsip_endpt_create(&cp.factory, "uniquesipendpointname", &sip_endpt);

	pool = pj_pool_create(&cp.factory, "parser_pool", 4000, 4000, NULL);

	pj_list_init(&err);

    size_t size = pr->get_size();

    for (size_t it = 0; it != size; ++it) {
		packet_reader::Info_and_Packet* testmsg = pr_->get_packet(it);
		parsing(testmsg->packet.data(), testmsg->sec, testmsg->usec, testmsg->ip, testmsg->port);
	}

}
Sip_Parser::~Sip_Parser() {
	pj_pool_release(pool);
	//pjsip_endpt_destroy(sip_endpt);
	//pj_shutdown();
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
        //= std::move(buf_info);
		if (auto search = sip_packets.find(call_id); search == sip_packets.end()) {
			std::vector<std::variant<Info_and_Sip_Packet, receive>> a, b;
			Key_and_Sides k_a_s {ip, port, std::move(a), std::move(b)};
			const auto [it, success] = sip_packets.insert(std::pair{call_id, std::move(k_a_s)});
		}

		if (auto search = sip_packets.find(call_id); search != sip_packets.end()) {
			//добавить условие по флагу стороны
            char* p = (char*)malloc(20);
            pj_ssize_t len;
            if (msg->type == PJSIP_REQUEST_MSG) {
                len = msg->line.req.method.name.slen;
                pj_memcpy(p, msg->line.req.method.name.ptr, len);
            }
            else {
                len = msg->line.status.reason.slen;
                pj_memcpy(p, msg->line.status.reason.ptr, len );
            }
            std::string str_msg_type = p;
            std::cout << str_msg_type.erase(len, str_msg_type.size()-len) << "\n";
            free(p);
            
			if (search->second.ip_ == ip && search->second.port_ == port) {
				search->second.a.push_back(std::move(buf_info));
                if (auto search2 = string_in_receive.find(str_msg_type); search2 != string_in_receive.end())
                    search->second.b.push_back(search2->second);
                else
                    search->second.b.push_back(ERROR);
            }
			else {
				search->second.b.push_back(std::move(buf_info));
                auto msg = buf_info.get_msg();
                if (auto search2 = string_in_receive.find(str_msg_type); search2 != string_in_receive.end())
                    search->second.a.push_back(search2->second);
                else
                    search->second.a.push_back(ERROR);
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
	pjsip_msg_print_user( msg, buf, SIZE_BUF);

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
            std::string buf_str;
            if(elem.index() == 0) {
                sip_parser::Info_and_Sip_Packet iasp = std::get<0>(elem);
                pjsip_msg_print_user(iasp.get_msg(), buf, SIZE_BUF);                                                                 
            }
            else {
                switch (std::get<1>(elem)) {
                    case INVITE:
                        buf_str = "receive INVITE\r\n";
                        break;
                    case ACK:
                        buf_str = "receive ACK\r\n";
                        break;
                    case BYE:
                        buf_str = "receive BYE\r\n";
                        break;
                    case TRYING:
                        buf_str = "receive TRYING\r\n";
                        break;
                    case RINGING:
                        buf_str = "receive RINGING\r\n";
                        break;
                    case OK:
                        buf_str = "receive OK\r\n";
                        break;
                    default:
                        buf_str = "ERROR\r\n";
                        break;
                }
            }
			if (buf_str.empty()) buf_str = buf;
            out_a << buf_str; 
			free(buf);
		}
		for (auto elem : key_and_sides.b) {
			char *buf = (char*)malloc(SIZE_BUF);
            std::string buf_str;
            if(elem.index() == 0) {
                sip_parser::Info_and_Sip_Packet iasp = std::get<0>(elem);
                pjsip_msg_print_user(iasp.get_msg(), buf, SIZE_BUF);                                                                 
            }
            else {
                switch (std::get<1>(elem)) {
                    case INVITE:
                        buf_str = "receive INVITE\r\n";
                        break;
                    case ACK:
                        buf_str = "receive ACK\r\n";
                        break;
                    case BYE:
                        buf_str = "receive BYE\r\n";
                        break;
                    case TRYING:
                        buf_str = "receive TRYING\r\n";
                        break;
                    case RINGING:
                        buf_str = "receive RINGING\r\n";
                        break;
                    case OK:
                        buf_str = "receive OK\r\n";
                        break;
                    default:
                        buf_str = "ERROR\r\n"; 
                        break;
                }
            }
			if (buf_str.empty()) buf_str = buf;
            out_b << buf_str; 
			free(buf);                                                                                 
		}
	}
	
	out_a.close();
	out_b.close();

}
std::map<Call_ID, Key_and_Sides>* Sip_Parser::get_sip_packets() {
	return &sip_packets;
}

void Sip_Parser::clear_sip_packets(){
	sip_packets.clear();
}
}