#pragma once
#include <stdint.h>
#include <pcap.h>
#include "all.h"

bool arpSend(pcap_t *handle,
             mac_addr srcMAC,
             mac_addr destMAC,
             uint16_t arpOpcode,
             ip_addr arpSrcIP,
             mac_addr arpSrcMAC,
             ip_addr arpDestIP,
             mac_addr arpDestMAC);