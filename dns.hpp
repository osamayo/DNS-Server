
#include <stdint.h>
#include <string>
#include <map>
#include <arpa/inet.h>
#include <sys/socket.h>


using namespace std;

// https://www.rfc-editor.org/rfc/rfc1035

typedef struct {
    uint16_t id; // identifier
    uint16_t flags;
    // unsigned char QR: 1; // specifies whether this message is a Query (0) or response (1)
    // unsigned short Opcode: 4; // type of Query [0] for standard Query
    // unsigned char AA: 1; // authoritave answer
    // unsigned char TC: 1; // truncation
    // unsigned char RD: 1; // recursion desired
    // unsigned char RA: 1; // recursion available
    // unsigned char Z: 3; // reserved for future use
    // unsigned char RCode: 4; // response code
    uint16_t QDCount; // number of Queries
    uint16_t ANCount; // number of answers
    uint16_t NSCount; // number of authority records
    uint16_t ARCount; // number of additional records section
} dns_header;

typedef struct {
    uint16_t QR;
    uint16_t Opcode;
    uint16_t AA;
    uint16_t TC;
    uint16_t RD;
    uint16_t RA;
    uint16_t Z;
    uint16_t RCode;
} dns_flags;

typedef struct {
    char* QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS; 
} dns_query;

typedef struct {
    uint16_t RDLENGTH;
    uint8_t o1;
    uint8_t o2;
    uint8_t o3;
    uint8_t o4;
} RR_A;

typedef struct {
    uint16_t RDLENGTH;
    char* CNAME;
} RR_CNAME;

typedef struct {
    uint16_t RDLENGTH;
    uint16_t PREFERENCE;
    char* MX;
} RR_MX;


typedef struct {
    uint16_t RDLENGTH;
    char* NS;
} RR_NS;

typedef struct {
    char NAME[2];

    uint16_t TYPE;
    uint16_t CLASS;
    uint16_t TTL_PAD;
    uint16_t TTL;
    

} dns_answer_header;

typedef struct {
    void* answerStruct;
    size_t answerSize;
} dns_answer;

typedef struct {
    dns_answer_header header;
    RR_A A;
        
} dns_ipv4_record;


#define DNS_CLASSES_COUNT 4
#define DNS_TYPES_COUNT 16
enum dns_class{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4
};

enum dns_qclass{
    Q_IN = 1,
    Q_CS = 2,
    Q_CH = 3,
    Q_HS = 4,
    Q_CLASS_ALL = 2
};

enum dns_type {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    TYPE_NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16
};

enum dns_qtype {
    Q_A = 1,
    Q_NS = 2,
    Q_MD = 3,
    Q_MF = 4,
    Q_CNAME = 5,
    Q_SOA = 6,
    Q_MB = 7,
    Q_MG = 8,
    Q_MR = 9,
    Q_TYPE_NULL = 10,
    Q_WKS = 11,
    Q_PTR = 12,
    Q_HINFO = 13,
    Q_MINFO = 14,
    Q_MX = 15,
    Q_TXT = 16,
    Q_AXFR = 252,
    Q_MAILB = 253,
    Q_MAILA = 254,
    Q_TYPE_ALL = 255
};


char* parse_qname(char* qname);
char* build_resource_name(char* name);
void parse_flags(uint16_t flags, dns_flags* dst);
uint16_t get_dns_flags(dns_flags flags);
char* construct_name_with_origin(char* name);

void hexDump (
    const char * desc,
    const void * addr,
    const int len,
    int perLine
); //#TODO: remove

enum RCODE {
    RC_NO_ERROR=0,
    RC_FORMAT_ERROR=1,
    RC_SERVER_FAILURE=2,
    RC_NAME_ERROR=3,
    RC_NOT_IMPLEMENTED=4,
    RC_REFUSED=5
};


/*
RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the Q_uery.

                2               Server failure - The name server was
                                unable to process this Q_uery due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the Q_uery does
                                not exist.

                4               Not Implemented - The name server does
                                not support the reQ_uested kind of Q_uery.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular reQ_uester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone transfer) for particular data.

                6-15            Reserved for future use.
*/


