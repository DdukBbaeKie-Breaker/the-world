#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <unordered_map>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "protocol/packet.h"
#include "protocol/all.h"

std::unordered_map<std::string , bool> ipDstBlocks;

mac_addr originGatwayMAC;
ip_addr originGatwayIP;

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}
}

bool equalIPAddr(ip_addr x, ip_addr y)
{
	return memcmp(&x, &y, sizeof(ip_addr)) == 0;
}

bool equalMACAddr(mac_addr x, mac_addr y)
{
	return memcmp(&x, &y, sizeof(mac_addr)) == 0;
}

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb, bool *isAccept) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		if (ntohs(ph->hw_protocol) == ETHERTYPE_IP)
		{
			ret = nfq_get_payload(tb, &data);
			if (ret >= 0)
			{
				int packetIndex = 0;
				const ip_header *ip = (ip_header *)data;
				packetIndex += sizeof(ip_header);
				char ipSrc[INET_ADDRSTRLEN];
				char ipDst[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(ip->ip_src), ipSrc, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(ip->ip_dst), ipDst, INET_ADDRSTRLEN);

				std::unordered_map<std::string, bool>::iterator rulesIt = ipDstBlocks. find(ipSrc);
				*isAccept = rulesIt != ipDstBlocks.end() ? false : true;

				printf("IP SRC : ");
				printIPAddress(ip->ip_src);
				printf("\n");
				printf("IP DEST : ");
				printIPAddress(ip->ip_dst);
				ip_addr temp;
				temp.a = 10;
				temp.b = 156;
				temp.c = 147;
				temp.d = 146;
				if(equalIPAddr(ip->ip_dst, temp)) {
					*isAccept = false;
				}
				printf("\n");
			}
		}
		fputc('\n', stdout);
	}
	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	bool *isAccept = new bool(true);
	uint32_t id = print_pkt(nfa, isAccept);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, *isAccept ? NF_ACCEPT : NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	std::cout << "[*] Tead Rules File..."<<std::endl;
	std::cout << argv[0] << std::endl;

	std::string binExeDir(argv[0]);
	std::string binExeDirBase = binExeDir.substr(0, binExeDir.find_last_of("/"));
	std::ifstream ipDstBlocksFile(binExeDirBase + "/ipDstBlock.txt");
	if (!ipDstBlocksFile)
	{
		std::cout << binExeDirBase + "/ipDstBlock.txt" << std::endl;
	}
	std::cout << binExeDirBase + "/ipDstBlock.txt" << std::endl;

	std::string ipDstBlocksStr;
	while(std::getline(ipDstBlocksFile, ipDstBlocksStr))
	{
		ipDstBlocks.insert(std::make_pair(ipDstBlocksStr, true));
	}
	std::cout << "[*] IP Block Rule Size : " << ipDstBlocks.size() << std::endl;
	std::cout << "[*] IP Block Rules Load Success" << std::endl;

	std::ifstream originGatwayIPFile(binExeDirBase + "originGatwayIP.txt");
	if(!originGatwayIPFile)
	{
		std::cout << "[*] File nt Exist << std:endl";
	}
	std::cout <<binExeDirBase + "originGatwayIPFile.txt" << std::endl;
	std::string originGatwayIPStr;
	while (std::getline(originGatwayIPFile, originGatwayIPStr))
	{
		sscanf(originGatwayIPStr.c_str(), "%d.%d.%d.%d", &originGatwayIP.a, &originGatwayIP.b, &originGatwayIP.c, &originGatwayIP.d);
	}

	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}