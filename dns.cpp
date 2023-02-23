#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include "dns-zone.hpp"

using namespace std;

void parse_flags(uint16_t flags, dns_flags* dst)
{
    uint8_t QR = flags >> 15;
    uint8_t OpCode = flags >> 11;
    OpCode = OpCode & 0xf;
    uint8_t AA = flags >> 10;
    AA = AA & 0x1;
    uint8_t TC = flags >> 9;
    TC = TC & 0x1;
    uint8_t RD = flags >> 8;
    RD = RD & 0x1;
    uint8_t RA = flags >> 7;
    RA = RA & 0x1;
    uint8_t Z = flags >> 4;
    Z = Z & 0x7;
    uint8_t RCODE = flags & 0xf;

    dst->QR = QR;
    dst->Opcode = OpCode;
    dst->AA = AA;
    dst->TC = TC;
    dst->RD = RD;
    dst->RA = RA;
    dst->Z = Z;
    dst->RCode = RCODE;
    printf("QR: %u | OpCode: %u | AA: %u | TC: %u | RD: %u | RA: %u | Z: %u | RCODE: %u\n", QR, OpCode, AA, TC, RD, RA, Z, RCODE);

    return;
}

uint16_t get_dns_flags(dns_flags flags_struct)
{
    uint16_t flags = 0;
    flags += flags_struct.QR << 15;
    flags += (flags_struct.Opcode&0xf) << 11;
    flags += (flags_struct.AA &0x1) << 10;
    flags += (flags_struct.TC &0x1) << 9;
    flags += (flags_struct.RD & 0x1) << 8;
    flags += (flags_struct.RA & 0x1) << 7;
    flags += (flags_struct.Z & 0x7) << 4;
    flags += (flags_struct.RCode & 0xf);
    return flags;
}

char* construct_name_with_origin(char* name)
{
    int size = strlen(name) + 3;
    char* name_with_origin = (char*)malloc(size);
    if (name_with_origin == NULL)
    {
        perror("Error while allocating name with malloc!\n");
        exit(3);
    }
    char origin_value[2];
    origin_value[0] = 0xc0;
    origin_value[1] = 0x0c;
    memset(name_with_origin, 0, size);
    memcpy(name_with_origin, name, strlen(name));
    memcpy(name_with_origin + strlen(name), origin_value, 2);
    
    return name_with_origin;
}

char* parse_qname(char* qname)
{
    size_t index_reader=0, index_writer=0, count = 0;
    
    
    char* name_parsed = (char*)malloc(strlen(qname));
    if (name_parsed == NULL)
    {
        perror("Error while allocating name with malloc!\n");
        exit(3);
    }
    
    while((count = *(qname+index_reader)) != 0)
    {
        index_reader += 1;
        strncpy(name_parsed + index_writer, qname + index_reader, count);
        strcat(name_parsed, ".");
        index_reader += count;
        index_writer += count + 1;
        
    }
    // printf("parsed name: %s\n", name_parsed);
    return name_parsed;
   
   
}

char* build_resource_name(char* name)
{
    char* resource = (char*)malloc(strlen(name) + 1);
    if (resource ==NULL)
    {
        perror("Error malloc construct resource name!");
        exit(3);
    }
    memset(resource, 0, strlen(name)+1);

    char* slice = strtok(name, ".");
    int index = 0;
    if (slice == NULL)
    {
        // no . found
        *resource = strlen(name);
        strcat(resource, name);
    } 
    
    while (slice != NULL)
    {
        *(resource+index) = strlen(slice);
        index +=1;
        strcat(resource, slice);
        index+= strlen(slice);
        slice = strtok(NULL, ".");
    }   
    return resource;
}


void hexDump (
    const char * desc,
    const void * addr,
    const int len,
    int perLine
) {
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64) perLine = 16;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL) printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}
