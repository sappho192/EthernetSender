#pragma once

#include <iostream>
#include <cstdlib>
#include <vector>

#include "pcap.h"

bool sendRawEthernet();
void printError(const char* func, int line, const char* err);

static const unsigned char packetQuery[] = {
	0xde,0xad,0xbe,0xef,0xfe,0xed,0x34,0xe6,0xd7,0x33,0x6e,0x5d,0x08,0x00,0x45,0x00,
	0x00,0x34,0x5e,0x41,0x40,0x00,0x80,0x06,0x00,0x00,0xc0,0xa8,0x01,0x01,0xc0,0xa8,
	0x01,0x78,0x07,0x4f,0x01,0xf6,0x1c,0xab,0xe2,0x10,0x00,0x00,0x91,0x01,0x50,0x18,
	0xff,0x00,0x83,0xf0,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x05,0x00,0x64,
	0xff,0x00
};
