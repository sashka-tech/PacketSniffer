#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

// display bytes of packet in hex
void packet_dump(const unsigned char *data_buffer, const unsigned int length) {
	u_char byte;
	for(u_int i=0; i < length; i++) {
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);
		if(((i%16)==15) || (i==length-1)) {
			for(u_int j=0; j < 15-(i%16); j++){
				printf("   ");
            }
			printf("| ");
			for(u_int j=(i-(i%16)); j <= i; j++) {
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)){
					printf("%c", byte);
                }
				else {
					printf(".");
                }
			}
			printf("\n");
		}
	}
}

void fatal_error(char *message) {
   char error_message[100];
   strcpy(error_message, "[!!] Fatal Error ");
   strncat(error_message, message, 83);
   perror(error_message);
   exit(-1);
}

// malloc() wrapper
void *ec_malloc(unsigned int size) {
   void *ptr;
   ptr = malloc(size);
   if(ptr == NULL)
      fatal_error("in ec_malloc() on memory allocation");
   return ptr;
}
