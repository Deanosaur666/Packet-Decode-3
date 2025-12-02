#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

// Terminal input for linux:
// gcc pd2.c ; ./a.out Frame2.bin

// let's read a binary file
int main(int argc, char *argv[]) {
	int errorcode = 0;				// returned at end of function
	FILE *file;						// file pointer
	unsigned char byte; 			// where we store the byte read
	unsigned int i = 0; 			// for counting bytes in payload

	// IHL is used to determine if we have options
	unsigned char IHL;				// internet header length 		(4 bits)
	// fields greater than 8 bits variables for storage, since we read 1 byte at a time
	unsigned int totalLength;		// IP header total length 		(16 bits)
	unsigned int identification;	// IP header identifications 	(16 bits)
	// it's more convenient to store this in a variable, since otherwise we have to shift for every bit check
	unsigned char flags;			// IP header flags				(3 bits)
	unsigned int fragmentOffset;	// IP header fragment offset	(13 bits)
	unsigned int checksum;			// IP checksum					(16 bits)

	printf("\n");

	// no filename passed
	if (argc < 2) {
		printf("You must provide an argument.");
		errorcode = 1;
	}
	// filename passed as argument
	else {
		file = fopen(argv[1], "rb");
		// couldn't open file
		if (file == NULL) {
			printf("The file cannot be opened");
			errorcode = 2;
		}
		// successfully opened file
		else {
			printf("Ethernet header:\n");
			printf("----------------\n");

			// first 6 bytes are Destination MAC Address
			printf("Destination MAC address:\t\t");

			// These two lines repeat throughout. They're the workhorse of this program.
			// We read one byte, then print it. Very simple.
			fread(&byte, sizeof(char), 1, file);
			printf("%02x", byte & 0xFF);

			// print the next 5 bytes with a colon preceding them
			for (int i = 0; i < 5; i++) {
				fread(&byte, sizeof(char), 1, file);
				printf(":%02x", byte & 0xFF);
			}

			// next 6 bytes are Source MAC Address
			printf("\nSource MAC address:\t\t\t");

			fread(&byte, sizeof(char), 1, file);
			printf("%02x", byte & 0xFF);

			for (int i = 0; i < 5; i++) {
				fread(&byte, sizeof(char), 1, file);
				printf(":%02x", byte & 0xFF);
			}

			// next 2 bytes are type
			printf("\nType:\t\t\t\t\t");

			fread(&byte, sizeof(char), 1, file);
			printf("%02x", byte & 0xFF);
			fread(&byte, sizeof(char), 1, file);
			printf("%02x", byte & 0xFF);
			
			// This is where the new stuff starts; the IP header
			printf("\n\nIPv4 Header:\n");
			printf("----------------\n");

			// Version and IHL
			fread(&byte, sizeof(char), 1, file);
			IHL = byte & 0xF;

			printf("Version:\t\t\t\t%02d\n", byte >> 4);		// decimal
			printf("Internet header length:\t\t\t%02x\n", IHL); // hex

			// DSCP and ECN
			fread(&byte, sizeof(char), 1, file);

			printf("DSCP:\t\t\t\t\t%02d\n", byte >> 2);				 // decimal
			printf("ECN:\t\t\t\t\t%d%d", (byte >> 1) & 1, byte & 1); // binary

			// ECN flag
			switch (byte & 0b11) {
				case 0:
					printf("\tNon-ECT Packet");
					break;
				// 0b01 and 0b10 are both identical
				case 1:
				case 2:
					printf("\tECN Capable Transport");
					break;
				case 3:
					printf("\tCongestion Experienced");
					break;
			}

			// Total length
			fread(&byte, sizeof(char), 1, file);
			totalLength = byte << 8; 	// I love bit shifting
			fread(&byte, sizeof(char), 1, file);
			totalLength |= byte;		// we could use "+=", but that's not as cool

			printf("\nTotal Length:\t\t\t\t%d\n", totalLength);

			// Identification
			fread(&byte, sizeof(char), 1, file);
			identification = byte << 8;
			fread(&byte, sizeof(char), 1, file);
			identification |= byte;

			printf("Identification:\t\t\t\t%d\n", identification);

			// Flags
			fread(&byte, sizeof(char), 1, file);
			flags = byte >> 5; // getting rid of fragment offset bits

			printf("Flags:\t\t\t\t");

			// don't fragment
			if(flags & 0b010)
				printf("\tDon't Fragment");

			// more fragments
			if(flags & 0b001) 	// I don't know if we'll ever have both 0b010 and 0b001 on (like 0b011),
								// so not making it "else if", just in case we ever need to show both
				printf("\tMore Fragments");

			// no flags
			else if(flags == 0)
				printf("\tNo Flag Set");

			// Fragment Offset
			fragmentOffset = (byte & 0b00011111) << 8; // masking off the 3 flag bits
			fread(&byte, sizeof(char), 1, file);
			fragmentOffset |= byte;

			printf("\nFragment Offset:\t\t\t%d\n", fragmentOffset);

			// Time to Live
			fread(&byte, sizeof(char), 1, file);
			printf("Time to Live:\t\t\t\t%d\n", byte);

			// Protocol
			fread(&byte, sizeof(char), 1, file);
			printf("Protocol:\t\t\t\t%d\n", byte);

			// IP Checksum
			fread(&byte, sizeof(char), 1, file);
			checksum = byte << 8;
			fread(&byte, sizeof(char), 1, file);
			checksum |= byte;

			// I don't know why we prefix with "0x" here but not for IHL...
			// but that's the format in the example
			printf("IP Checksum:\t\t\t\t0x%04x\n", checksum);

			// Souce IP Address
			printf("Source IP Address:\t\t\t");
			fread(&byte, sizeof(char), 1, file);
			printf("%d", byte);

			for(int i = 0; i < 3; i ++) {
				fread(&byte, sizeof(char), 1, file);
				printf(".%d", byte);
			}

			// Destination IP Address
			printf("\nDestination IP Address:\t\t\t");
			fread(&byte, sizeof(char), 1, file);
			printf("%d", byte);

			for(int i = 0; i < 3; i ++) {
				fread(&byte, sizeof(char), 1, file);
				printf(".%d", byte);
			}

			// Options
			if(IHL <= 5) {
				printf("\nOptions:\t\t\t\tNo Options");
			}
			else {
				// Option Word Count = IHL - 5
				for(int i = 0; i < IHL - 5; i ++) {
					printf("\nIP Option Word #%d:\t\t\t0x", i);
					// we don't need to store the whole word in an int or anything,
					// since printing bytes is just printing 2 hex digits at a time, left to right
					// a 32 bit word is 4 bytes, of course
					for(int j = 0; j < 4; j ++) {
						fread(&byte, sizeof(char), 1, file);
						printf("%02x", byte);
					}
				}
			}

			// the rest is payload
			printf("\n\nPayload:\n");

			// read, process, read
			// this prevents us from printing the last byte twice
			fread(&byte, sizeof(char), 1, file);
			while (!feof(file)) {
				i++;
				printf("%02x ", byte & 0xFF);
				if (i % 32 == 0)
				{
					printf("\n");
				}
				else if (i % 8 == 0)
				{
					printf(" ");
				}
				fread(&byte, sizeof(char), 1, file);
			}

			// We're done with the file! Good work everyone.
			fclose(file);
		}

		// I accidentally had fclose(file) here, but didn't get docked points for it
		// hee hee
	}

	printf("\n");
	return errorcode;
}
