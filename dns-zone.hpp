
#include "dns.hpp"
#include <map>

using namespace std;

typedef struct {
    uint32_t ttl;
    union
    {
        RR_A ipv4;
		RR_CNAME cname;
		RR_MX mx;
		RR_NS ns;
    } record;
    
} dns_zone_record;

dns_answer* handle_query(dns_query* query);

void init_dns_zone( );
void add_record(std::string, int Class, int Type, dns_zone_record* record);
void create_record_entry(std::string Name);
dns_zone_record* get_record(std::string Name, int Class, int Type);

// {"example.com.": [  // class 
//     [   // type
//         [TTL, record] // dns_zone_record
//     ]
// ]}


/*
$ORIGIN example.com. 
$TTL 86400 
@	IN	SOA	dns1.example.com.	hostmaster.example.com. (
			2001062501 ; serial                     
			21600      ; refresh after 6 hours                     
			3600       ; retry after 1 hour                     
			604800     ; expire after 1 week                     
			86400 )    ; minimum TTL of 1 day  
		     
		           
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




