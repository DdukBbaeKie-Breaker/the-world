#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"
#include "protocol/packet.h"

void printTCPPort(uint16_t port)
{
	printf("%d", port);
}

void printPacket(const unsigned char *p, uint32_t size)
{
	int len;
	while (len < size) {
		if(!(len % 16)) {
			printf("%04X ", len);
		}
		printf("%02X ", *(p+len));
		if(!(len+1) % 8){
			printf("   ");
		}
		len++;
		if(!((len) % 16) || (size - len) == 0)
		{
			int length = (size -len) == 0 ? size % 16 : 16;
			if(length < 16){
				for(int i=0;i < 16 - length; i++) {
					printf("   ");
					if(!((i+1) % 8)){
						printf("   ");
					}
				}
			}
			for(int i = 0; i<length; i++) {
				uint8_t nowChar = *(p+(len-(length-i)));
				if(nowChar >= 33 && nowChar <= 126) {
					printf("%c ", nowChar);
				}
				else {
					printf(". ");
				}
				if(!((i+1) % 8)) {
					printf("   ");
				}
			}
			printf("\n");
		}
	}
}
void printMACAddress(mac_addr mac)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X \n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printIPAddress(ip_addr ipAddr)
{
	printf("%d.%d.%d.%d\n", ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

const void *http_header[] = 
{
    HTTP_METHOD_HTTP,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_CONNECT, 
    HTTP_METHOD_OPIONS,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_PATCH
};