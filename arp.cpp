#include "arp.h"

void send_arp(pcap_t* handle, ArpHdr::Operation arp_opcode, Mac source_mac, Ip source_ip, Mac target_mac, Ip target_ip){
    EthArpPacket packet;

	packet.eth_.dmac_ = target_mac;
	packet.eth_.smac_ = source_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(arp_opcode);
	packet.arp_.smac_ = source_mac;
	packet.arp_.sip_ = htonl(source_ip);
    if (arp_opcode == ArpHdr::Request)
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    else 
        packet.arp_.tmac_ = target_mac;
	packet.arp_.tip_ = htonl(target_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

EthArpPacket receive_arp(pcap_t* handle, Ip sender_ip) {
    EthArpPacket* packet;
    while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet_;
    int res = pcap_next_ex(handle, &header, &packet_);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    packet = (EthArpPacket*) packet_;

    if ((*packet).eth_.type_ != htons(EthHdr::Arp)) continue;
    if ((*packet).arp_.sip_ != Ip(htonl(sender_ip))) continue;
    if ((*packet).arp_.op_ != htons(ArpHdr::Reply)) continue;
    break;
  }
  return *packet;
}

Ip get_my_ip(const char* dev) {
    struct ifreq ifr;
    struct sockaddr_in * addr = (struct sockaddr_in *)&ifr.ifr_addr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        puts("Error");
        close(fd);
        exit(1);
    } 
    else {
        close(fd);
        return Ip(inet_ntoa(addr->sin_addr));
    }
}

Mac get_my_mac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    char buf[32];

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
        puts("Error");
        close(fd);
        exit(1);
    }
    else {
        close(fd);
        for (int i=0; i<MAC_ADDR_LEN; i++) 
            sprintf(&buf[i*3],"%02x:",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
        buf[MAC_ADDR_LEN*3 - 1]='\0';
        return Mac(buf);
    }
}