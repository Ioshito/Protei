#include <sip_parser/sip_parser.hpp>

void read_space(std::string& p, int n_space) {
    std::string space;
    for (int i = 0; i < n_space; ++i) {
        space += ' ';
    }
    p.insert(0, space);
    for (int i = 0; i < p.size(); ++i) {
        if (p[i] == '\n' && i+1 != p.size()) {
            p.insert(++i, space);
            i+=n_space;
        }
    }
}

template <typename T>
std::string toString(T val)
{
    std::ostringstream oss;
    oss<< val;
    return oss.str();
}

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
                                    char *buf, pj_size_t size, std::string& reg_exp)
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
    int abc = 0;
    /* Print each of the headers. */
    for (hdr=msg->hdr.next; hdr!=&msg->hdr; hdr=hdr->next) {
        len = pjsip_hdr_print_on(hdr, p, end-p);                
        p += len;                                               
        *p = '\0';
        p -= len;
        if (len < 0) {
           if (len == -2) {
               PJ_LOG(5, ("sip_msg", "Header with no vptr encountered!! "\
                          "Current buffer: %.*s", (int)(p-buf), buf));
           }
           return len;
        }
//                        
// [0][1][2][3][4][\0]
        if (len > 0) {
            auto& obj = obj_config::Obj_Config::Instance();
            nlohmann::json* json = obj.get_json();
            bool flag = 0;
            for (auto& it : json->items()) {
                std::cmatch result;
                std::regex regular(it.key());
                if(std::regex_search(p, result, regular)) {
                    flag = 1;
                    p += it.key().size();
                    memset(p, 0, len - it.key().size()+1);
                    *p++ = ' ';
                    if (it.value().is_null())
                        std::cout << "EMPTY: " << it.key() << "\n";
                    std::string cpp_string = it.value();
                    strcpy(p, cpp_string.c_str());
                    p += cpp_string.size();
                    *p++ = '\r';
                    *p++ = '\n';
                    break;
                }
            }
            if (!flag) {
                p += len;
                if (p+3 >= end)
                    return -1;

                if (hdr->type == PJSIP_H_CALL_ID) {
                    *p++ = '/';
                    *p++ = '/';
                    *p++ = '/';
                    *p++ = '[';
                    *p++ = 'c';
                    *p++ = 'a';
                    *p++ = 'l';
                    *p++ = 'l';
                    *p++ = '_';
                    *p++ = 'i';
                    *p++ = 'd';
                    *p++ = ']';
                }
                *p++ = '\r';
                *p++ = '\n';
            }
            
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

namespace sip_parser {

std::string begin_msg_sipp = "<?xml version=\"1.0\" encoding=\"us-ascii\"?>\r\n<scenario>\r\n\r\n";
std::string end_msg_sipp = "<ResponseTimeRepartition value=\"10, 20, 30, 40, 50, 100, 150, 200\" />\r\n<CallLengthRepartition value=\"10, 50, 100, 500, 1000, 5000, 10000\" />\r\n</scenario>";

std::map<Call_ID, Key_and_Sides> Sip_Parser::sip_packets;

std::unordered_map<std::string, type_msg> string_in_type_msg {{"INVITE", INVITE}, {"ACK", ACK}, {"BYE", BYE}, {"Trying", TRYING}, {"Ringing", RINGING}, {"OK", OK}};

pjsip_endpoint * Sip_Parser::sip_endpt;

Info_and_Sip_Packet::Info_and_Sip_Packet(){}

Info_and_Sip_Packet::Info_and_Sip_Packet(long sec, long usec, std::string ip, int port, pjsip_msg *msg, type_msg t_msg)
    : sec_(sec), usec_(usec), ip_(ip), port_(port), t_msg_(t_msg) {
	copy = msg;
}

Info_and_Sip_Packet::Info_and_Sip_Packet(pjsip_msg *msg) {
	copy = msg;
}

pjsip_msg* Info_and_Sip_Packet::get_msg() {
	return copy;
}

type_msg Info_and_Sip_Packet::get_type_msg() {
    return t_msg_;
}

long Info_and_Sip_Packet::get_sec() {
    return sec_;
}


Sip_Parser::Sip_Parser(packet_reader::Packet_Reader_Interface *pr, std::string& reg_exp): pr_(pr), reg_exp_(reg_exp) {
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

        // Если не существует записи с таким call_id       
		if (auto search = sip_packets.find(call_id); search == sip_packets.end()) {
			std::vector<std::variant<Info_and_Sip_Packet, receive_type_msg>> a, b;
			Key_and_Sides k_a_s {ip, port, std::move(a), std::move(b)};
			const auto [it, success] = sip_packets.insert(std::pair{call_id, std::move(k_a_s)});
		}

        // Если существует запись с таким call_id
		if (auto search = sip_packets.find(call_id); search != sip_packets.end()) {
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
            str_msg_type.erase(len, str_msg_type.size()-len);
            free(p);
            

            receive_type_msg rtm;
            if (auto search2 = string_in_type_msg.find(str_msg_type); search2 != string_in_type_msg.end())
                    rtm.t_msg = search2->second;
                else
                    rtm.t_msg = ERROR;

            Info_and_Sip_Packet buf_info (sec, usec, ip, port, msg, rtm.t_msg);
            if (search->second.ip_ == ip && search->second.port_ == port) {
				search->second.a.push_back(std::move(buf_info));
                search->second.b.push_back(std::move(rtm));
            }
            else {
				search->second.b.push_back(std::move(buf_info));
				search->second.a.push_back(std::move(rtm));
            }




            /*
			if (search->second.ip_ == ip && search->second.port_ == port) {
				search->second.a.push_back(std::move(buf_info));
                if (auto search2 = string_in_type_msg.find(str_msg_type); search2 != string_in_type_msg.end())
                    search->second.b.push_back( std::move( receive_type_msg {search2->second} ) );
                else
                    search->second.b.push_back( std::move( receive_type_msg { ERROR } ) );
            }
			else {
				search->second.b.push_back(std::move(buf_info));
                if (auto search2 = string_in_type_msg.find(str_msg_type); search2 != string_in_type_msg.end())
                    search->second.a.push_back( std::move( receive_type_msg {search2->second} ) );
                else
                    search->second.a.push_back( std::move( receive_type_msg { ERROR } ) );
			}
            */
		}
	}
	else {
		std::cout << "ERROR";
	}
}

void Sip_Parser::read_in_file(std::ofstream& out, const std::vector<std::variant<Info_and_Sip_Packet, receive_type_msg>>& vec) {
	// READ
    long buf_sec;
    bool flag = 0;
	for (auto elem : vec) {
            std::string result;
            std::string end_result = "        ]]>\r\n</send>\r\n";
            if(elem.index() == 0) {
                result = "<send retrans=\"500\">\r\n        <![CDATA[\r\n";
                sip_parser::Info_and_Sip_Packet iasp = std::get<0>(elem);

                if (flag == 1) {
                    out <<  "<pause milliseconds=\"" + toString((iasp.get_sec() - buf_sec) * 1000) + "\"/>\r\n";
                }

                if (iasp.get_type_msg() == ACK) {
                    result = "<send crlf=\"true\">\r\n        <![CDATA[\r\n";
                    flag = 1;
                    buf_sec = iasp.get_sec();
                }
                if (iasp.get_type_msg() == TRYING) {
                    result = "<send>\r\n        <![CDATA[\r\n";
                    end_result = "        ]]>\r\n</send>\r\n<pause milliseconds=\"100\"/>\r\n";
                }
                if (iasp.get_type_msg() == RINGING) {
                    result = "<send>\r\n        <![CDATA[\r\n";
                    end_result = "        ]]>\r\n</send>\r\n<pause milliseconds=\"500\"/>\r\n";
                }
			    
                char *buf = (char*)malloc(SIZE_BUF);
                
                pjsip_msg_print_user(iasp.get_msg(), buf, SIZE_BUF, reg_exp_);
                std::string buf_str = buf;
    			free(buf);
                read_space(buf_str, 16);          
                result += std::move(buf_str);
                result += end_result;
            }
            else {
                switch (std::get<1>(elem).t_msg) {
                    case INVITE:
                        result += "<recv request=\"INVITE\"";
                        break;
                    case ACK:
                        result += "<recv request=\"ACK\"  crlf=\"true\"";
                        break;
                    case BYE:
                        result += "<recv request=\"BYE\"";
                        break;
                    case TRYING:
                        result += "<recv response=\"100\"";
                        break;
                    case RINGING:
                        result += "<recv response=\"180\"";
                        break;
                    case OK:
                        result += "<recv response=\"200\"";
                        break;
                    default:
                        result += "\"ERROR\"";
                        break;
                }
                result += " />\r\n";
            }
            out << result; 
		}

}

void Sip_Parser::read_in_files(const std::string& name) {
	// READ
	

	for (const auto& [call_id, key_and_sides] : sip_packets) {
        std::ofstream out_a, out_b;
        out_a.open(toString(call_id.substr(9)) + "_A_side_" + name + ".xml");
        out_a << begin_msg_sipp;
    
        out_b.open(toString(call_id.substr(9)) + "_B_side_" + name + ".xml");
        out_b << begin_msg_sipp;
        
		read_in_file(out_a, key_and_sides.a);
		read_in_file(out_b, key_and_sides.b);

        out_a << end_msg_sipp;
	    out_a.close();

        out_b << end_msg_sipp;
	    out_b.close();
	}
	
    

}
std::map<Call_ID, Key_and_Sides>* Sip_Parser::get_sip_packets() {
	return &sip_packets;
}

void Sip_Parser::clear_sip_packets(){
	sip_packets.clear();
}
} // namespace