#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
enum returncodes {
	SUCCESS,
	ERROR_CHECKSUM,
	ERROR_VERSION_6,
	ERROR_VERSION_UNKNOWN,
	ERROR_INSUFFICIENT_DATA,
	ERROR_BAD_HEADER_LENGTH,
	ERROR_BAD_LENGTH ,
	__ERR_MAX
};
static const char * const errorstrings[__ERR_MAX] = {
	"SUCCESS", /* SUCCESS */
	"Incorrect checksum", /* ERROR_CHECKSUM */
	"Version is IPv6", /* ERROR_VERSION_6 */
	"Version is neither IPv4 nor IPv6", /* ERROR_VERSION_UNKNOWN */
	"The value of the length field is less than a common IP structure", /* ERROR_INSUFFICIENT_DATA */
	"The value of the header length field is less than a common IP structure", /* ERROR_BAD_HEADER_LENGTH */
	"The value of the packet length field is less than the value of the header length field" /* ERROR_BAD_LENGTH */
};

#define GET_ERROR_STRING(i) errorstrings[i]

int ip_parse(const uint8_t *buffer, uint length);
