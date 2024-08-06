#include <gtest/gtest.h>
#include <iostream>
#include <packet_reader/packet_reader.hpp>

namespace {
TEST(packet_reader, packet_reader_two_dialog_INVITE_one) {
  char msg0[] = {
  "INVITE tel:+79217654321 SIP/2.0\r\n"
  "Via: SIP/2.0/UDP 127.0.0.103:1899;branch=z9hG4bK-73277-1-0\r\n"
  "From: <sip:+79011234567@protei.ru>;tag=uac1-73277@127.0.0.103\r\n"
  "To: <tel:+79217654321>\r\n"
  "Call-ID: 1-73277@127.0.0.103\r\n"
  "CSeq: 1 INVITE\r\n"
  "Contact: sip:127.0.0.103:1899\r\n"
  "Max-Forwards: 70\r\n"
  "Content-Type: application/sdp\r\n"
  "Content-Length:   221\r\n"
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
  std::string buf = msg0;
  
  try {
    packet_reader::Packet_Reader_Offline pr("../../../packets_pcap_test/call_flow_04.pcap");
    pr.processing(0);

    packet_reader::Info_and_Packet* testmsg = pr.get_packet(0);
  
    EXPECT_EQ(testmsg->packet, buf);
  } catch (const char* error_message) {
    FAIL() << error_message << "\n";
  }
}

TEST(packet_reader, packet_reader_two_dialog_100) {
  char msg0[] = {
  "SIP/2.0 100 Trying\r\n"
  "Via: SIP/2.0/UDP 127.0.0.103:1899;branch=z9hG4bK-73277-1-0\r\n"
  "From: <sip:+79011234567@protei.ru>;tag=uac1-73277@127.0.0.103\r\n"
  "To: <tel:+79217654321>\r\n"
  "Call-ID: 1-73277@127.0.0.103\r\n"
  "CSeq: 1 INVITE\r\n"
  "Contact: <sip:127.0.1.1:5060;transport=UDP>\r\n"
  "Content-Length: 0\r\n"
  "\r\n"
  };
  std::string buf = msg0;
  
  
  packet_reader::Packet_Reader_Offline pr("../../../packets_pcap_test/call_flow_04.pcap");
  pr.processing(0);

  packet_reader::Info_and_Packet* testmsg = pr.get_packet(1);

  EXPECT_EQ(testmsg->packet, buf);
  
}

TEST(packet_reader, packet_reader_two_dialog_INVITE_two) {
  char msg0[] = {
  "INVITE tel:+79215559977 SIP/2.0\r\n"
  "Via: SIP/2.0/UDP 127.0.0.201:3945;branch=z9hG4bK-73279-1-0\r\n"
  "From: <sip:+79014442233@protei.ru>;tag=uac1-73279@127.0.0.201\r\n"
  "To: <tel:+79215559977>\r\n"
  "Call-ID: 1-73279@127.0.0.201\r\n"
  "CSeq: 1 INVITE\r\n"
  "Contact: sip:127.0.0.201:3945\r\n"
  "Max-Forwards: 70\r\n"
  "Content-Type: application/sdp\r\n"
  "Content-Length:   221\r\n"
  "\r\n"
  "v=0\r\n"
  "o=BasicCallUAC 1328079155 1 IN IP4 127.0.0.201\r\n"
  "s=BasicCall\r\n"
  "c=IN IP4 127.0.0.201\r\n"
  "t=0 0\r\n"
  "m=audio 3947 RTP/AVP 8 101\r\n"
  "a=rtpmap:8 PCMA/8000\r\n"
  "a=rtpmap:101 telephone-event/8000\r\n"
  "a=fmtp:101 0-15\r\n"
  "a=ptime:20\r\n"
  "a=sendrecv\r\n"
  };
  std::string buf = msg0;
  
  
  packet_reader::Packet_Reader_Offline pr("../../../packets_pcap_test/call_flow_04.pcap");
  pr.processing(0);

  packet_reader::Info_and_Packet* testmsg = pr.get_packet(2);

  EXPECT_EQ(testmsg->packet, buf);
  
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

