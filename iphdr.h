#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final{
    uint8_t  hl_:4;      /* header length */
    uint8_t  v_:4;         /* version */

    uint8_t  tos_;       /* type of service */

    uint16_t len_;         /* total length */
    uint16_t id_;          /* identification */
    uint16_t off_;

    uint8_t  ttl_;          /* time to live */
    uint8_t  p_;            /* protocol */
    uint16_t sum_;         /* checksum */
    
    Ip       sip_;
    Ip       dip_;
};
#pragma pack(pop)
