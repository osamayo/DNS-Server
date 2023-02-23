#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "dns-zone.hpp"

// {"example.com.": [  // class 
//     [   // type
//         [TTL, record] // dns_zone_record
//     ]
// ]}
/*
$ORIGIN example.com. 
$TTL 86400 
		           
	IN	NS	dns1.example.com.       
	IN	NS	dns2.example.com.        	
	
	IN	MX	10	mail.example.com.       
	IN	MX	20	mail2.example.com.        
	
dns1	IN	A	10.0.1.1
dns2	IN	A	10.0.1.2	
			       
server1	IN	A	10.0.1.5        
server2	IN	A	10.0.1.6
       
ftp	IN	A	10.0.1.3
	IN	A	10.0.1.4
	
mail	IN	CNAME	server1
mail2	IN	CNAME	server2

www	IN	CNAME	server1
*/

#define ORIGIN example.com.
#define DEFAULT_TTL 8640

using namespace std;   

std::map<std::string, dns_zone_record***> zone;



void init_dns_zone( )
{
    dns_zone_record* example_ip = (dns_zone_record*) malloc(sizeof(dns_zone_record));
    example_ip->ttl = 0;
    example_ip->record.ipv4.o1 = 11;
    example_ip->record.ipv4.o2 = 22;
    example_ip->record.ipv4.o3 = 33;
    example_ip->record.ipv4.o4 = 44;
    example_ip->record.ipv4.RDLENGTH = 4;

    add_record("example.com.", IN, A, example_ip);
    
    dns_zone_record* example_cname = (dns_zone_record*) malloc(sizeof(dns_zone_record));
    example_cname->ttl = 300;
    char* cname_name = strdup("www");
    cname_name = build_resource_name(cname_name);
    cname_name = construct_name_with_origin(cname_name);
    hexDump("cname name", cname_name, strlen(cname_name) + 3, 8);    
    example_cname->record.cname.CNAME = cname_name;
    example_cname->record.cname.RDLENGTH = strlen(cname_name);
    add_record("example.com.", IN, CNAME, example_cname);

    dns_zone_record* example_mx = (dns_zone_record*) malloc(sizeof(dns_zone_record));
    example_mx->ttl = 400;
    char* mx_name = strdup("smtp");
    mx_name = build_resource_name(mx_name);
    mx_name = construct_name_with_origin(mx_name);
    hexDump("mx name", mx_name, strlen(mx_name) + 3, 8);
    example_mx->record.mx.MX = mx_name;
    example_mx->record.mx.PREFERENCE = 10;
    example_mx->record.mx.RDLENGTH = strlen(example_mx->record.mx.MX) + 2; // 2 bytes for pref number
    add_record("example.com.", IN, MX, example_mx);

    dns_zone_record* example_ns = (dns_zone_record*) malloc(sizeof(dns_zone_record));
    example_ns->ttl = 600;
    char* ns_name = strdup("ns1");
    ns_name = build_resource_name(ns_name);
    ns_name = construct_name_with_origin(ns_name);
    hexDump("ns name", ns_name, strlen(ns_name) + 3, 8);
    example_ns->record.ns.NS = ns_name;
    example_ns->record.ns.RDLENGTH = strlen(example_ns->record.ns.NS);
    add_record("example.com.", IN, NS, example_ns);


    
    // dns_zone_record* r = get_record("example.com.", IN, NS);
    // if (r == NULL)
    // {
    //     puts("Not found!\n");
    // } else 
    // {
    //     printf("ttl: %d | NS: %d, %s\n", r->ttl, r->record.ns.RDLENGTH, r->record.ns.NS);
    // }
   
}

void add_record( std::string Name, int Class, int Type, dns_zone_record* record)
{
    Class -= 1;
    Type -= 1;
    if (Class < DNS_CLASSES_COUNT && Type < DNS_TYPES_COUNT){
        //#TODO: append origin
        if (record->ttl == 0)
        {
            record->ttl = DEFAULT_TTL;
        }
        
        if (zone.find(Name) == zone.end())
        {
            create_record_entry(Name);
        }

        dns_zone_record*** classes = zone[Name];
        *(*(classes + Class) + Type) = record;
    }
}

void create_record_entry( std::string Name)
{
    // if no entry for the record is found in the hashmap
    dns_zone_record*** classes= (dns_zone_record***) malloc(sizeof(dns_zone_record*) * DNS_CLASSES_COUNT);
    if (classes != NULL)
    {
        for (int i=0; i<DNS_CLASSES_COUNT; i++)
        {
            dns_zone_record** type = (dns_zone_record**) malloc(sizeof(dns_zone_record*) * DNS_TYPES_COUNT);
            if (type == NULL)
            {
                perror("Error while allocating zone records with malloc!\n");
                exit(6);
            }
            *(classes + i) = type;
        }
    } else 
    {
        perror("Error while allocating zone records with malloc!\n");
        exit(6);
    }
    zone.insert(make_pair(Name, classes));


}

dns_zone_record* get_record( std::string Name, int Class, int Type)
{
    Class -= 1;
    Type -= 1;
    if (zone.find(Name) != zone.end() && Class < DNS_CLASSES_COUNT && Type< DNS_TYPES_COUNT)
    {
        dns_zone_record*** classes = zone[Name];
        dns_zone_record* record;
        record = *(*(classes + Class) + Type);
        return record;
    } else 
    {
        printf("Name or record not found\n");
        printf("Class: %d | Type: %d\n", Class, Type);
    }
    return NULL; 
}

dns_answer* handle_query(dns_query* query) {
    char* name_parsed = parse_qname(query->QNAME);
    int Class = query->QCLASS;
    int Type = query->QTYPE;

    std::string name_p(name_parsed);

    dns_zone_record* zone_resource = get_record(name_p, Class, Type);
    if (zone_resource != NULL)
    {
        dns_answer_header* header = (dns_answer_header*)malloc(sizeof(dns_answer_header));
        dns_answer* answer = (dns_answer*) malloc(sizeof(dns_answer));
        if (header == NULL || answer == NULL)
        {
            perror("Error while allocating resource with malloc!\n");
            exit(2);
        }
        // Origin name
        header->NAME[0] = 0xc0;
        header->NAME[1] =  0x0c;
        header->TYPE = htons(query->QTYPE);
        header->CLASS = htons(query->QCLASS);
        header->TTL_PAD = htons(0);
        header->TTL = htons(zone_resource->ttl);

        printf("resource: %d %d %d\n", ntohs(header->TYPE), ntohs(header->CLASS), ntohs(header->TTL));
        
        if (Type == A)
        {
            puts("Resource Record A\n");
            dns_ipv4_record* resource = (dns_ipv4_record*) malloc(sizeof(dns_ipv4_record));
            if (resource == NULL)
            {
                perror("Error while allocationg resource!");
                exit(2);
            }
            resource->header = *header;
            resource->A = zone_resource->record.ipv4;
            resource->A.RDLENGTH = htons(zone_resource->record.ipv4.RDLENGTH);
            answer->answerStruct = (void*) resource;
            answer->answerSize = sizeof(*resource);

        } else if (Type == CNAME)
        {
            puts("Resource Record CNAME\n");
            int rdLen = zone_resource->record.cname.RDLENGTH;
            printf("rdLen: %d\n", rdLen);
            int size = sizeof(dns_answer_header) + rdLen + 2;
            void* cname_record = (void*) malloc(size);

            if (cname_record == NULL)
            {
                perror("Error while allocationg resource!");
                exit(2);
            }

            memcpy(cname_record, (void*)header, sizeof(dns_answer_header));
            uint16_t rdlength = htons(rdLen);
            memcpy(cname_record + sizeof(dns_answer_header), (void*)(&rdlength), 2);
            memcpy(cname_record + sizeof(dns_answer_header) + 2, (void*)(zone_resource->record.cname.CNAME), rdLen);


            hexDump("NS Record", cname_record, size, 8);

            answer->answerStruct = cname_record;
            answer->answerSize = size;
        } else if (Type == MX)
        {
            puts("Resource Record MX\n");
            int rdLen = zone_resource->record.mx.RDLENGTH;
            printf("rdLen: %d\n", rdLen);
            int size = sizeof(dns_answer_header) + rdLen + 4;
            void* mx_record = (void*) malloc(size);

            if (mx_record == NULL)
            {
                perror("Error while allocationg resource!");
                exit(2);
            }

            memcpy(mx_record, (void*)header, sizeof(dns_answer_header));
            uint16_t rdlength = htons(rdLen);
            memcpy(mx_record + sizeof(dns_answer_header), (void*)(&rdlength), 2);
            uint16_t preferences = htons(zone_resource->record.mx.PREFERENCE);
            memcpy(mx_record + sizeof(dns_answer_header) + 2, (void*)(&preferences), 2);
            memcpy(mx_record + sizeof(dns_answer_header) + 4, (void*)(zone_resource->record.mx.MX), rdLen);


            hexDump("MX Record", mx_record, size, 8);

            answer->answerStruct = mx_record;
            answer->answerSize = size;
        } else if (Type == NS)
        {
            puts("Resource Record NS\n");
            int rdLen = zone_resource->record.ns.RDLENGTH;
            printf("rdLen: %d\n", rdLen);
            int size = sizeof(dns_answer_header) + rdLen + 2;
            void* ns_record = (void*) malloc(size);

            if (ns_record == NULL)
            {
                perror("Error while allocationg resource!");
                exit(2);
            }

            memcpy(ns_record, (void*)header, sizeof(dns_answer_header));
            uint16_t rdlength = htons(rdLen);
            memcpy(ns_record + sizeof(dns_answer_header), (void*)(&rdlength), 2);
            memcpy(ns_record + sizeof(dns_answer_header) + 2, (void*)(zone_resource->record.ns.NS), rdLen);


            hexDump("NS Record", ns_record, size, 8);

            answer->answerStruct = ns_record;
            answer->answerSize = size;
            
        }        
        return answer;

    } else 
    {
        // not found resource
        return NULL;    
    }
    
}
