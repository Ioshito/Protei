#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <iostream>
#include <sip_parser/sip_parser.hpp>
#include <packet_reader/packet_reader.hpp>

using ::testing::Return;

class Packet_Reader_Mock : public packet_reader::Packet_Reader_Interface {
public:
  ~Packet_Reader_Mock() override = default;
  MOCK_METHOD(void, set_filter, (const std::string&));
  MOCK_METHOD(void, processing, (int));
  MOCK_METHOD(void, read_in_file, (const std::string&));

  MOCK_METHOD(size_t, get_size, (), (const));
  MOCK_METHOD(packet_reader::Info_and_Packet*, get_packet, (size_t));
};

namespace {
TEST(sip_parser, sip_parser) {
  // Arrange
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
  packet_reader::Info_and_Packet buf{0, 0, ip, 1899, buffer};
  
  Packet_Reader_Mock prM;
  EXPECT_CALL(prM, get_size()).Times(1).WillOnce(Return(1));
  EXPECT_CALL(prM, get_packet(0)).Times(1).WillOnce(Return(&buf));

  // Act
  sip_parser::Sip_Parser sp(&prM);


  // Assert
  std::map<sip_parser::Call_ID, sip_parser::Key_and_Sides>* sip_packets = sp.get_sip_packets();

  std::string buf_str;
  for (const auto& [call_id, key_and_sides] : *sip_packets) {
  for (auto elem : key_and_sides.a) {
    char *buf = (char*)malloc(SIZE_BUF);
    if(elem.index() == 0) {
        sip_parser::Info_and_Sip_Packet iasp = std::get<0>(elem);
        pjsip_msg_print_user(iasp.get_msg(), buf, SIZE_BUF);                                                                 
    }
    else {
        sip_parser::type_msg r = std::get<1>(elem).t_msg;
        switch (r) {
            case sip_parser::INVITE:
                buf_str = "receive INVITE";
            case sip_parser::ACK:
                buf_str = "receive ACK";
            case sip_parser::BYE:
                buf_str = "receive BYE";
        }
    }
		if (buf_str.empty()) buf_str = buf;                                                              
  	free(buf);
  }                                                             
  }
  
  EXPECT_EQ(buf_str, buffer);
  sp.clear_sip_packets();
}


TEST(sip_parser, sip_parser_2) {
  // Arrange
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
  packet_reader::Info_and_Packet buf{0, 0, ip2, 1899, buffer2};

  Packet_Reader_Mock prM;
  EXPECT_CALL(prM, get_size()).Times(1).WillOnce(Return(1));
  EXPECT_CALL(prM, get_packet(0)).Times(1).WillOnce(Return(&buf));
  
  // Act
  sip_parser::Sip_Parser sp(&prM);

  // Assert
  std::map<sip_parser::Call_ID, sip_parser::Key_and_Sides>* sip_packets = sp.get_sip_packets();

  std::string buf_str;

  for (const auto& [call_id, key_and_sides] : *sip_packets) {
  for (auto elem : key_and_sides.a) {
    char *buf = (char*)malloc(SIZE_BUF);
    if(elem.index() == 0) {
        sip_parser::Info_and_Sip_Packet iasp = std::get<0>(elem);
        pjsip_msg_print_user(iasp.get_msg(), buf, SIZE_BUF);                                                                 
    }
    else {
        sip_parser::type_msg r = std::get<1>(elem).t_msg;
        switch (r) {
            case sip_parser::INVITE:
                buf_str = "receive INVITE";
            case sip_parser::ACK:
                buf_str = "receive ACK";
            case sip_parser::BYE:
                buf_str = "receive BYE";
        }
    }
		if (buf_str.empty()) buf_str = buf;                                                              
  	free(buf);
  }                                                             
  }
  EXPECT_EQ(buf_str, buffer2);
}


}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

