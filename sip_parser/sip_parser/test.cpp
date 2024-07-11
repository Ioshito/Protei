#include <gtest/gtest.h>
#include <iostream>
#include <sip_parser/sip_parser.hpp>

namespace {
TEST(sip_parser, sip_parser) {
  sip_parser::Sip_Parser sp;

  char msg0[] = {
    "INVITE tel:+79217654321 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 127.0.0.103:1899;branch=z9hG4bK-73277-1-0\r\n"
    "To: <tel:+79217654321>\r\n"
    "Call-ID: 1-73277@127.0.0.103\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:127.0.0.103:1899>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 221\r\n"
    "\r\n"
    "v=0\r\n"
    "o=BasicCallUAC 1328079155 1 IN IP4 127.0.0.103\r\n"
    "s=BasicCall\r\n"
    "c=IN IP4 127.0.0.103\r\n"
    "t=0 0\r\n"
    "m=audio 4580 RTP/AVP 8 101\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-15\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n"
  };

  std::string buffer = msg0;
  std::string ip = "127.0.0.103";
  sp.parsing(buffer.data(), 0, 0, ip, 1899);
  std::map<sip_parser::Call_ID, sip_parser::Key_and_Sides>* sip_packets = sp.get_sip_packets();

  std::string buf_str;
  for (const auto& [call_id, key_and_sides] : *sip_packets) {
  for (auto elem : key_and_sides.a) {
  	char *buf = (char*)malloc(SIZE_BUF);
  	pjsip_msg_print_user(elem.get_msg(), buf, SIZE_BUF);                                                                 
  	buf_str = buf;
  	free(buf);
  }                                                             
  }
  EXPECT_EQ(buf_str, buffer);
  sp.clear_sip_packets();
}

TEST(sip_parser, sip_parser_2) {
  sip_parser::Sip_Parser sp2;

  char msg1[] = {
    "ACK sip:127.0.1.1:5060;transport=UDP SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 127.0.0.101:3902;branch=z9hG4bK-68185-1-5\r\n"
    "To: <tel:+79217654321>;tag=uas1\r\n"
    "Call-ID: 1-68185@127.0.0.101\r\n"
    "CSeq: 1 ACK\r\n"
    "Contact: <sip:127.0.0.101:3902>\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Length: 0\r\n"
  };

  std::string buffer2 = msg1;

  std::string ip2 = "127.0.0.103";
  sp2.parsing(buffer2.data(), 0, 0, ip2, 1899);
  std::map<sip_parser::Call_ID, sip_parser::Key_and_Sides>* sip_packets2 = sp2.get_sip_packets();

  std::string buf_packets;

  for (const auto& [call_id2, key_and_sides2] : *sip_packets2) {
  for (auto elem2 : key_and_sides2.a) {
  	char *buf2 = (char*)malloc(SIZE_BUF);
  	pjsip_msg_print_user(elem2.get_msg(), buf2, SIZE_BUF);                                                                 
  	std::string buf_str = buf2;
    buf_packets = std::move(buf_str);
  	free(buf2);
  }                                                             
  }
  EXPECT_EQ(buf_packets, buffer2);
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

