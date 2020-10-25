#include <unistd.h>  
#include <string>  
#include <sys/socket.h>  
#include <sys/ioctl.h>  
#include <sys/stat.h>  
#include <netinet/in.h>  
#include <net/if.h>  
#include <arpa/inet.h> 
#include <pcap.h>
#include "arphdr.h"
#include "ethhdr.h"
#include "iphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIp4Packet {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

#define MAC_BROADCAST "FF:FF:FF:FF:FF:FF"
#define MAC_ADDR_LEN 6

struct MacIpPair {
	Ip ip;
	Mac mac;
};

void send_arp(pcap_t* handle, ArpHdr::Operation arp_opcode,  Mac source_mac, Ip source_ip, Mac target_mac, Ip target_ip);
EthArpPacket receive_arp(pcap_t* handle, Ip sender_ip);
Ip get_my_ip(const char* dev);
Mac get_my_mac(const char* dev);