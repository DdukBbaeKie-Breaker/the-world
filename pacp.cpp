#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocol/all.h"

void usage()
{
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    uint8_t buffer[1500];
    int packetIndex = 0;
    ether_header eth;
    eth.ether_type = htons(ETHERTYPE_ARP);
    mac_addr src;
    src.oui[0] = 0x00;
    src.oui[1] = 0x0c;
    src.oui[2] = 0x29;
    src.nic[0] = 0x8f;
    src.nic[1] = 0xb7;
    src.nic[2] = 0xc3;
    eth.src = src;

    mac_addr dest;
    dest.oui[0] = 0xFF;
    dest.oui[1] = 0xFF;
    dest.oui[2] = 0xFF;
    dest.nic[0] = 0xFF;
    dest.nic[1] = 0xFF;
    dest.nic[2] = 0xFF;
    eth.dst = dest;
    memcpy(buffer, &eth, sizeof(ether_header));
    packetIndex += sizeof(ether_header);

    arp_header arp;

    arp.hardware_type = htons(ARPHRD_ETHER);
    arp.protocol_type = htons(ARPPRO_IPV4);
    arp.hardware_size = 6;
    arp.protocol_size = 4;
    arp.opcode = htons(ARPOP_REQUEST);
    arp.sender_mac = {{0x00, 0x0c, 0x29}, {0x8f, 0xb7, 0xc3}};
    arp.sender_ip = {192, 168, 5, 135}; 
    arp.target_mac = {{0x00, 0x00, 0x00},{0x00, 0x00, 0x00}};
    arp.target_ip = {192, 168, 5, 2};

    memcpy(buffer+packetIndex, &arp, sizeof(arp_header));
    packetIndex += sizeof(arp_header);

    while (true)
    {
        if (pcap_sendpacket(handle, buffer, packetIndex) != 0)
        {
            printf("Send Fail.\n");
        }
    }

    pcap_close(handle);
    return 0;
}