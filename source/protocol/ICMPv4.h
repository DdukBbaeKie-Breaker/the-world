#pragma once
#include <stdint.h>

struct icmpv4
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
};