#include <cstdio>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <cstdbool>
#include "dns-zone.hpp"


#define PORT 53
#define PACKET_MAX_SIZE 1024

using namespace std;

void handleClient(int, struct sockaddr_in*, int);




int main()
{

    // init dns zone
    init_dns_zone();

    int sock;
    struct sockaddr_in server_ip, client_ip;
    int lengthClientStruct = sizeof(struct sockaddr_in);
    int lengthServerStruct = sizeof(struct sockaddr_in);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    // bind port
    server_ip.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_ip.sin_family = AF_INET;
    server_ip.sin_port = htons(PORT);
    if (bind(sock, (struct sockaddr*)&server_ip, lengthServerStruct) < 0)
    {
        perror("Error while binding\n");
        exit(-1);
    }
    
    puts("Starting DNS Server");
    
    while (true)
    {
        handleClient(sock, &client_ip, lengthClientStruct);
        puts("Handle next client");
    }

    close(sock);
    return 0;

}


void handleClient(int sock, struct sockaddr_in* client, int lengthStruct)
{

    // init buffer
    dns_header queryHeader;
    memset(&queryHeader, 0, sizeof(dns_header));
    char buffer[PACKET_MAX_SIZE];
    memset(&buffer, 0, PACKET_MAX_SIZE);

    int recievedLen;
    if ((recievedLen = recvfrom(sock, &buffer, PACKET_MAX_SIZE, 0, (sockaddr*)client, (socklen_t*)&lengthStruct)) > 0)
    {   
        memcpy(&queryHeader, &buffer, sizeof(dns_header));
        uint16_t id = ntohs(queryHeader.id);
        uint16_t QDCount = ntohs(queryHeader.QDCount);
        uint16_t NSCount = ntohs(queryHeader.NSCount);
        uint16_t ARCount = ntohs(queryHeader.ARCount);

        printf("id: %d | QDCount: %d\n", id, QDCount);
        
        // parse flags
        uint16_t flagsValue = ntohs(queryHeader.flags);
        dns_flags flagsStruct;
        parse_flags(flagsValue, &flagsStruct);

       

        if (QDCount != 0)
        {
            dns_answer** answers = (dns_answer**) malloc(QDCount * sizeof(dns_answer*));
            if (answers == NULL)
            {
                perror("Error while allocating resources with malloc\n");
                exit(1);
            }
            size_t queryReader = sizeof(dns_header);
            int answersCount = 0; // count how many responses
            //#TODO: Create answer index
            for (int i=0; i<QDCount; i++)
            {
                dns_query query;
                
                size_t qname_len = strlen(buffer + queryReader);
               
               
                char* QNAME = (char*)malloc(qname_len);
                if (QNAME == NULL)
                {
                    perror("Erorr while allocating QNAME with malloc!\n");
                    exit(4);
                }

                memset(QNAME, 0, qname_len);
                strncpy(QNAME, buffer + queryReader, qname_len);
                
                                
                queryReader += qname_len + 1;// +1 for the null byte

                query.QNAME = QNAME;

                memcpy(&query.QTYPE, buffer + queryReader, 2);
                queryReader += 2;
                query.QTYPE = ntohs(query.QTYPE);

                memcpy(&query.QCLASS, buffer + queryReader, 2);
                queryReader += 2;
                query.QCLASS = ntohs(query.QCLASS);

                printf("QNAME: %s\n", query.QNAME);
                printf("Type: %d | Class: %d\n", query.QTYPE, query.QCLASS);
                printf("___________________________________________________\n");
                dns_answer* answer= handle_query(&query);
                if (answer == NULL)
                {
                    flagsStruct.RCode = RC_NAME_ERROR;
                    continue;
                }

                *(answers+i) = handle_query(&query);
                answersCount += 1;
                
            }
            dns_header response_header;
            // Recursion unavailable, response flag
            flagsStruct.RA = 0;
            flagsStruct.QR = 1;
            uint16_t flags = get_dns_flags(flagsStruct);

            response_header.flags = htons(flags);
            response_header.id = htons(id);
            response_header.QDCount = htons(QDCount);
            response_header.ANCount = htons(answersCount);
            response_header.NSCount = htons(NSCount);
            response_header.ARCount = htons(ARCount);

            // set response header
            memcpy(&buffer, &response_header, sizeof(dns_header));

            // loop answers

            for (int i=0; i<answersCount; i++)
            {
                dns_answer* answer = *(answers + i);
                size_t resource_size = answer->answerSize;
                hexDump("Resource", answer->answerStruct, resource_size, 16);

                memcpy(buffer + queryReader, answer->answerStruct, resource_size);
                queryReader += resource_size;
            }
            // hexDump("Packet to send", &buffer, queryReader, 16);
            sendto(sock, &buffer, queryReader, 0, (sockaddr*)client, lengthStruct);
        } else 
        {
            puts("Queries count is zero!\n");
        }
    } else
    {
        puts("Error while recieving data from client\n");
    }

}
