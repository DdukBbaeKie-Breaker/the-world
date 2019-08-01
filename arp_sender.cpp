#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "packet.h"
#include "protocol/all.h"

int main(int argcm char *argv[])
{
	char interface[IFNAMSIZ];
	char senderIPStr[15];
	char targetIPStr[15];
	char senderMACtr[17];
	char targetMACtr[17]
	arp.arp_target_mac = 
	arp.arp_target_ip = (0.0.0.0);

if (argc == 6)
{
	strncpy(interface, argv[1], IFNAMSIZ);
	strncpy(senderIPStr, argv[2], strlen(argv[2]));
	strncpy(senderMacStr, argv[3], strlen(argv[3]));
	strncpy(targetIPStr, argv[4], strlen(argv[4]));
	strncpy(targetMacStr, argv[5], strlen(argv[5]));
}
else
{
	print("ERROR\n");
	return -1;
}


}
if(4 == sscanf(senderIPStr, "%d.%d.%d.%d", &senderIP.a, &senderIP.b ,&senderIP.c ,&senderIP.d))
{
	return -1;
}
if(6 == sscanf(senderMACtr, "%hhx:%hhx:%hhx:%hhx", &senderMAC.a, &senderMAC.b, &senderMAC.c, &senderMAC.d ,&senderMAC.e ,&senderMAC.f))
