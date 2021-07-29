#ifndef _LIN_H
#define _LIN_H

#include <stdint.h>

#define LIN_MESSAGE_FRAME 0
#define LIN_MESSAGE_EVENT 1

#define LIN_CHECKSUM_UNKNOWN 0
#define LIN_CHECKSUM_CLASSIC 1
#define LIN_CHECKSUM_ENHANCED 2

#define LIN_ERROR_OVERFLOW 	0x20 // Overflow Error
#define LIN_ERROR_INVALIDID	0x10 // Invalid ID, i.e.a frame ID of 0x3E or 0x3F has been received
#define LIN_ERROR_CHECKSUM 	0x08 // Checksum Error
#define LIN_ERROR_PARITY 	0x04 // Parity Error
#define LIN_ERROR_FRAMING 	0x02 // Framing Error
#define LIN_ERROR_NOSLAVE 	0x01 // No Slave Response Error


struct lin_frame
{
	uint8_t rev = 1;
	uint8_t _reserved1 = 0;
	uint8_t _reserved2 = 0;
	uint8_t _reserved3 = 0;
	uint8_t checksum_type : 2;
	uint8_t message_type : 2;
	uint8_t payload_length : 4;
	uint8_t pid = 0;
	uint8_t checksum = 0;
	uint8_t errors = 0;
	uint8_t data[8];

	lin_frame() {
		payload_length = 0;
		message_type = LIN_MESSAGE_FRAME;
		checksum_type = LIN_CHECKSUM_UNKNOWN;
	}
};

#endif