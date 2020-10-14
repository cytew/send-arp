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

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Mac my_Mac;
Ip my_Ip;

void ArpAttack(pcap_t* handle, const Mac my_Mac, const char* send_Ip, const char* tar_Ip);

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


Mac GetMyMacAddr(const char* ifname){ //https://tttsss77.tistory.com/138
    
    struct ifreq ifr;
    int sockfd, ret;
	uint8_t macAddr[MAC_ALEN];
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    
    memcpy(macAddr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    return macAddr;
}

Ip GetMyIp(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    char ipAddr[40];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipAddr, sizeof(struct sockaddr));
    //change network info to char LE
	//sockaddr: 2byte family 14byte IP+Port

    return Ip(ipAddr);
}


int main(int argc, char* argv[]) {

	int cnt=1;
	
	if ((argc%2)!=0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	my_Mac=GetMyMacAddr(argv[1]);
	my_Ip=GetMyIp(argv[1]);

	printf("myMac: %s\n",my_Mac.operator std::string().c_str());
	printf("myIp: %s\n",my_Ip.operator std::string().c_str()); //c_str: exchange string to char*

	printf("------------------------------------------------\n");
	for(int i=2;i<argc;i+=2){
		printf("Attack Num:%d\n",cnt);
		ArpAttack(handle, my_Mac, argv[i], argv[i+1]);
		cnt++;
		printf("------------------------------------------------\n");
	}

	pcap_close(handle);
}
