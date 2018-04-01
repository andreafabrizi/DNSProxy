/*
 * Copyright (c) 2013-2018 Massimiliano Fantuzzi HB3YOE <max@fantuz.net> <superfantuz@gmail.com>

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

*/

#include <fcntl.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <sys/timeb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <signal.h>
#include <pthread.h>
#include "b64.h"

//#include <base64.h>
//#include "hexdump.h"

/*
#include <semaphore.h>
#include <spawn.h>
#include <omp.h>
*/
#define errExit(msg)		do { perror(msg); exit(EXIT_FAILURE); } while (0)
#define handle_error(msg)	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define VERSION           "2"

/* Stack size for cloned child */
#define STACK_SIZE (1024 * 1024)    
/* DELAY for CURL to wait ? do not remember, needs documentation */
#define DELAY		    0

/* how can it be influenced, this CURL MAXCONN parameter ? */
/* kept for historical reasons, will not be useful in threaded model but comes back with H2 */
#define MAXCONN          	    2
#define UDP_DATAGRAM_SIZE	  512
#define TCP_DATAGRAM_SIZE	 4096
#define DNSREWRITE       	  512
#define HTTP_RESPONSE_SIZE	 4096
#define URL_SIZE		  512
#define DNS_MODE_ANSWER  	    0
#define DNS_MODE_ERROR   	    1
#define TYPEQ		    	    2
#define DEFAULT_LOCAL_PORT	   53
#define DEFAULT_WEB_PORT 	   80
#define DEFAULT_PRX_PORT 	 1080

/* experimental options for threaded model, not in use at the moment */
#define NUMT			    2
#define NUM_THREADS		    2
#define NUM_HANDLER_THREADS	    1

/* use nghttp2 library to establish, no ALPN/NPN */
/* not yet ready as CURL seems to suffice, and NGHTTP2 is C++ */
#define USE_NGHTTP2		    1

#define STR_SIZE 65536

#define PORT 53

#ifndef CURLPIPE_MULTIPLEX
#error "too old libcurl, can't do HTTP/2 server push!"
#endif

//#define for_each_item(item, list) \
//	    for(T * item = list->head; item != NULL; item = item->next)

/* This little trick will just make sure that we don't enable pipelining for
   libcurls old enough to not have this symbol. It is _not_ defined to zero in
   a recent libcurl header. */ 
//#ifndef CURLPIPE_MULTIPLEX
//#define CURLPIPE_MULTIPLEX 0
//#endif
 
#ifndef SOMAXCONN
#define SOMAXCONN 1
#endif

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
 
#define NUM_HANDLES 4

#define OUTPUTFILE "dl"

int DEBUG, DNSDUMP, DEBUGCURL, EXT_DEBUG;
char* substring(char*, int, int);

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
 
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
 
    *output_length = 4 * ((input_length + 2) / 3);
 
    char *encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;
 
    for (int i = 0, j = 0; i < input_length;) {
 
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
 
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
 
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
 
    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';
 
    return encoded_data;
}

void copy_string(char *target, char *source) {
   while (*source) {
      *target = *source;
      source++;
      target++;
   }
   *target = '\0';
}
 
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
 
    if (decoding_table == NULL) build_decoding_table();
 
    if (input_length % 4 != 0) return NULL;
 
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
 
    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;
 
    for (int i = 0, j = 0; i < input_length;) {
 
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
 
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
 
        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
 
    return decoded_data;
}
 
void build_decoding_table() {
    decoding_table = malloc(256);
 
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}
 
void base64_cleanup() {
    free(decoding_table);
}

static void *curl_hnd[NUM_HANDLES];
static int num_transfers = 1;

/* this part is to configure default behaviour when initialising threads */
pthread_key_t glob_var_key_ip;
pthread_key_t glob_var_key_client;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
//static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
//pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
pthread_mutexattr_t MAttr;

#ifdef TLS
__thread int i;
#else
 pthread_key_t key_i;
#endif
 pthread_t *tid;

struct readThreadParams {
    size_t xrequestlen;
    char* xproxy_user;
    char* xproxy_pass;
    char* xproxy_host;
    int xproxy_port;
    char* xlookup_script;
    char* xtypeq;
    int xwport;
    int xttl;
    int sockfd;
    int xsockfd;
    //int digit;
    //char* input;
    struct dns_request *xhostname;
    struct sockaddr_in *xclient;
    struct sockaddr_in *yclient;
    struct dns_request *xproto;
    //struct dns_request *xdns_req;
    struct dns_request *dns_req;
};

struct thread_info {    	/* Used as argument to thread_start() */
    pthread_t thread_id;        /* ID returned by pthread_create() */
    int       thread_num;       /* Application-defined thread # */
    char     *argv_string;      /* From command-line argument */
};

/*
void start_thread(pthread_t *mt)
{
    mystruct *data = malloc(sizeof(*data));
    ...;
    pthread_create(mt, NULL, do_work_son, data);
}
*/

/*
void start_thread(pthread_t *mt)
{
    //mystruct local_data = {};
    //mystruct *data = malloc(sizeof(*data));
    struct readThreadParams local_data = {};
    struct readThreadParams *data = malloc(sizeof(*data));
    *data = local_data;
    //pthread_create(mt, NULL, threadFunc,readParams);
    pthread_create(mt, NULL, thread_start,data);
    //pthread_create(mt, NULL, threadFunc,data);
    //ret = pthread_create(&pth[i],NULL,threadFunc,readParams);
    //pthread_create(&pth[i],NULL,threadFunc,readParams);
}
*/

static void *thread_start(void *arg) {
   struct thread_info *tinfo = arg;
   char *uargv, *p;

   printf("Thread %d: top of stack near %p; argv_string=%s\n",
            tinfo->thread_num, &p, tinfo->argv_string);

   uargv = strdup(tinfo->argv_string);
   if (uargv == NULL)
        handle_error("strdup");

   for (p = uargv; *p != '\0'; p++)
        *p = toupper(*p);

   return uargv;
}

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

//static void hexdump(void *mem, unsigned int len) {
static void *hexdump(void *mem, unsigned int len) {
        unsigned int i, j;
        
        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        //printf("0x%06x: ", i);
                        printf("%04x: ", i);
                }
 
                /* print hex data */
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        printf("   ");
                }
                
                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        putchar(0xFF & ((char*)mem)[j]);        
                                }
                                else /* other char */
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
                }
        }
}

//struct thread_data{
//	int threads;
//	int thread_id;
//	int exec; //total number of executions 
//	int max_req_client;
//	int random; //1=yes 0=no whether requests are the max or randomdouble
//	int ssl; //1=yes 0=no
//	int uselogin; //1=yes 0=no
//	char domain[256];
//	char login[256];
//	char password[256];
//};

struct dns_request
{
    uint16_t transaction_id,
             questions_num,
             flags,
             qtype,
             qclass,
             tcp_size;
    char hostname[256],
             query[256];
    size_t hostname_len;
};  

struct dns_response
{
    size_t length;
    char *payload;
};

void usage(void) {
    fprintf(stderr, "\n dnsp %s, copyright @ 2018 Massimiliano Fantuzzi, MIT License\n\n"
                       " usage: dnsp-h2 [-l [local_host]] [-p [local_port:53,5353,..]] [-H [proxy_host]] [-r [proxy_port:8118,8888,3128,9500..]] \n"
		       "\t\t [-w [lookup_port:80,443,..]] [-s [lookup_script]]\n\n"
                       " OPTIONS:\n"
                       "      -l\t\t Local server address	(optional)\n"
                       "      -p\t\t Local server port	(optional, defaults to 53)\n"
                       "      -H\t\t Cache proxy address	(strongly suggested)\n"
                       "      -r\t\t Cache proxy port	(strongly suggested)\n"
                       "      -u\t\t Cache proxy username	(optional)\n"
                       "      -k\t\t Cache proxy password	(optional)\n"
                       "      -s\t\t Lookup script URL	(mandatory option)\n"
                       "      -w\t\t Lookup port		(obsolete, defaults to 80/443 for HTTP/HTTPS)\n"
                       "\n"
                       " TESTING/DEV OPTIONS:\n"
                       "      -T\t\t Force TTL to be [0-2147483647] as per RFC 2181 (useful for testing, 4 bytes)\n"
                       "      -n\t\t Enable DNS UDP RAW FORMAT DUMP\n"
                       "      -v\t\t Enable DEBUG\n"
                       "      -X\t\t Enable EXTRA_DEBUG\n"
                       "      -C\t\t Enable CURL VERBOSE, useful to spot cache issues or dig down into HSTS/HTTPS quirks\n"
                       " WIP OPTIONS:\n"
                       "      -I\t\t Upgrade Insecure Requests, HSTS work in progress\n"
                       "      -R\t\t Enable CURL resolve mechanism, avoiding extra gethostbyname (DO NOT USE)\n"
                       "      -t\t\t Stack size in format	0x1000000 (MB)\n"
                       "\n"
		       " Example HTTPS direct :  dnsp -s https://php-dns.appspot.com/\n"
		       " Example HTTP direct  :  dnsp -s http://www.fantuz.net/nslookup.php\n"
                       " Example HTTP w/cache :  dnsp -r 8118 -H http://myproxy.example.com/ -s http://www.fantuz.net/nslookup.php\n\n"
    ,VERSION);
    exit(EXIT_FAILURE);
}

/* Prints an error message and exit */
void error(const char *msg) {
    fprintf(stderr," *** %s: %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

/* Prints debug messages */
void debug_msg(const char* fmt, ...) {
    va_list ap;

    if (DEBUG) {
        fprintf(stdout, " [%d]> ", getpid());
        va_start(ap, fmt);
        vfprintf(stdout, fmt, ap); 
        va_end(ap);
    }
}

int generic_print(const void *ptr, size_t n) {
    printf("%x\n", ptr);
}

/* SHUFFLES OPPORTUNE MSB/LSB AGAINST NETWORK BYTE ORDER */
void *be32(void *ptr, unsigned long int n) {
    unsigned char *bp = ptr;
    
    bp[3] = n & 0xff;
    bp[2] = n >> 8 & 0xff;
    bp[1] = n >> 16 & 0xff;
    bp[0] = n >> 24 & 0xff;
    /*
    bp[7] = n & 0xff;
    bp[6] = n >> 8 & 0xff;
    bp[5] = n >> 16 & 0xff;
    bp[4] = n >> 24 & 0xff;
    bp[3] = n >> 32 & 0xff;
    bp[2] = n >> 40 & 0xff;
    bp[1] = n >> 48 & 0xff;
    bp[0] = n >> 56 & 0xff;
    */
    return ptr;
}

/* Return the length of the pointed buffer */
size_t memlen(const char *buff) {
    size_t len = 0;
    
    while (1) {
        if (buff[len] == 0) break;
        len ++;       
    }

    return len;
}

/* Parses the dns request and returns the pointer to dns_request struct. Returns NULL on errors */
struct dns_request *parse_dns_request(const char *udp_request, size_t request_len, int proton) {
    struct dns_request *dns_req;

    /* proto TCP, first 2 octets represent the UDP wire-format size */
    if (proton  == 1) {
      dns_req = malloc(sizeof(struct dns_request) + 2);
      if (DNSDUMP) {
        printf("\n *** TCP detected .. dns_req->tcp_size IN	: %08x // %d", (uint8_t) dns_req->tcp_size,dns_req->tcp_size);
        printf("\n *** TCP detected .. sizeof(udp_request) IN	: %08x // %d\n", (uint8_t) sizeof(udp_request),sizeof(udp_request));
      }
      //udp_request//response[1] = (uint8_t)(dns_req->transaction_id >> 8);
      dns_req->tcp_size = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8);
      udp_request+=2;
    } else {
      dns_req = malloc(sizeof(struct dns_request));
      if (DNSDUMP) { printf("\n *** UDP detected .. sizeof(udp_request) IN	: %08x // %d\n", (uint8_t) sizeof(udp_request),sizeof(udp_request)); }
    }

    /* Transaction ID */
    dns_req->transaction_id = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8);
    udp_request+=2;

    /* Flags */
    dns_req->flags = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8);
    udp_request+=2;

    /* Questions num */
    dns_req->questions_num = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8); 
    udp_request+=2;

    //if (EXT_DEBUG) { printf("\n *** QNUM ... %d\n", dns_req->questions_num); }

    /* WHERE IS EDNS ?? */

    /* Skipping 6 not interesting bytes, override with shortened answers (one of the initial purpose of DNSP software) */
    /*
       uint16_t Answers number 
       uint16_t Records number 
       uint16_t Additionals records number 
    */

    /* answers, authority, additional ? */
    udp_request+=6;
    
    /* Getting the dns query */
    bzero(dns_req->query, sizeof(dns_req->query));
    memcpy(dns_req->query, udp_request, sizeof(dns_req->query)-1);
    
    /* Hostname */
    bzero(dns_req->hostname, sizeof(dns_req->hostname));
    dns_req->hostname_len = 0;

    while (1) {
        uint8_t len = udp_request[0]; /* Length of the next label */
        if (len == 0) {
            udp_request++;
            break;
        }

        udp_request++;
        if (dns_req->hostname_len + len >=  sizeof(dns_req->hostname)) {
	    printf("CORE: size issue ! Maybe TCP ?\n");
            //free(dns_req);
            return NULL;
        }

        strncat(dns_req->hostname, udp_request, len); /* Append the current label to dns_req->hostname */
        strncat(dns_req->hostname, ".", 1); /* Append a '.' */
        dns_req->hostname_len+=len+1;
        udp_request+=len;
    }

    /* Qtype */
    dns_req->qtype = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8); 
    udp_request+=2;

    /* Qclass */
    dns_req->qclass = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8); 
    udp_request+=2;
        
    return dns_req;
}

/* Builds and sends the dns response datagram */
void build_dns_response(int sd, struct sockaddr_in *yclient, struct dns_request *dns_req, const char *ip, int mode, size_t xrequestlen, int ttl, int protoq) {
    char *rip = malloc(256 * sizeof(char));
    //struct dns_request *dns_req;
    //struct sockaddr_in *client;
    //char *str, *arg;
    //struct readThreadParams *params = malloc(sizeof(struct readThreadParams));
    //struct readThreadParams *params = (struct readThreadParams*)arg;
    //str=(char*)arg;
    
    int sockfd; // = params->xsockfd;
    int xsockfd; // = params->xsockfd;
    //struct dns_request *xhostname = (struct dns_request *)xhostname->hostname;
    char *response,
         *finalresponse,
	 *qhostname, // = dns_req->hostname,
         *token,
         *pch,
	 *maxim,
	 *rr,
	 *tt,
         *response_ptr,
         *finalresponse_ptr;
	 //typeq,
    //uint i,ppch;
    int i,ppch;
    ssize_t bytes_sent;
    ssize_t bytes_encoded;

    if (DEBUG) {
	    printf("\nBUILD-yclient->sin_addr.s_addr		: %u\n", (uint32_t)(yclient->sin_addr).s_addr);
	    printf("BUILD-yclient->sin_port			: %u\n", (uint32_t)(yclient->sin_port));
	    printf("BUILD-yclient->sin_family		: %d\n", (uint32_t)(yclient->sin_family));
	    printf("BUILD-xrequestlen			: %d\n", (uint32_t)(xrequestlen));
	    printf("BUILD-ttl				: %d\n", (uint32_t)(ttl));
	    printf("BUILD-Xsockfd				: %u\n", xsockfd);
	    printf("BUILD- sockfd				: %d\n", sockfd);
	    printf("BUILD-proto				: %d\n", protoq);
	    printf("BUILD-hostname UDP			: %s\n", dns_req->hostname);
	    //printf("BUILD-hostname				: %s\n", qhostname);
	    //printf("BUILD-xhostname-int				: %u\n", (uint32_t)strlen(xhostname));
	    //printf("build-qry = %s\n",(xdns_req->query));
    	    //printf("build-host = %s\n",(char *)(xdns_req->hostname));

	    //printf("%s\n", b64_encode((dns_req->hostname),sizeof(dns_req->hostname)));
	    //printf("ff						: %s\n", hexdump(dns_req->query[0], 512));
	    //char *xx = base64_encode(response_ptr, 64, 64);
	    //char xx = base64_encode(dns_req->hostname, (uint8_t)(xrequestlen)-1, (uint8_t)(xrequestlen)-1);
	    //printf(xx);
	    //printf("base64-hostname				: %s\n", base64_encode(tt, sizeof(dns_req->hostname), 512));
	    //printf("base64-hostname				: %s\n", xx); 
    	    //printf("base64-hostname				: %s\n", Base64encode(rr, dns_req->hostname, (uint8_t)(xrequestlen)));
    }

    response = malloc (UDP_DATAGRAM_SIZE);
    bzero(response, UDP_DATAGRAM_SIZE);

    finalresponse = malloc (TCP_DATAGRAM_SIZE);
    bzero(finalresponse, TCP_DATAGRAM_SIZE);

    maxim = malloc (DNSREWRITE);
    bzero(maxim, DNSREWRITE);

    //maxim_ptr = maxim;
    response_ptr = response;
    finalresponse_ptr = finalresponse;

    /* DNS header added when using TCP, represents the lenght in 2-bytes for the corresponding UDP/DNS usual wireformat. limit 65K */
    if (protoq == 1) {
      if (DNSDUMP) { printf(" *** TCP HEADER ON DNS WIRE PACKET: read tcp_size		: %d\n",(uint8_t)(dns_req->tcp_size)); }
      if (DNSDUMP) { printf(" *** TCP HEADER ON DNS WIRE PACKET: read dns_req		: %d\n",(uint8_t)(sizeof(dns_req) - 2)); }
      int norm = (dns_req->tcp_size + finalresponse - finalresponse_ptr);
      //response[0] = 0x00;
      //response[1] = 0x35; // testing with 55 bytes responses, as for A news.infomaniak.com
      response[0] = (uint8_t)(norm >> 8);
      response[1] = (uint8_t)norm;
      //response[0] = (uint8_t)(dns_req->tcp_size >> 8);
      //response[1] = (uint8_t)dns_req->tcp_size;
      //response[1] = sizeof(response_ptr); // 55 bytes
      response+=2;
    }

    /* Transaction ID */
    response[0] = (uint8_t)(dns_req->transaction_id >> 8);
    response[1] = (uint8_t)dns_req->transaction_id;
    response+=2;

    /*
    	TXT, SRV, SOA, PTR, NS, MX, DS, DNSKEY, AAAA, A, unused
    	A IPv4 host address 0x0001
    	AAAA IPv6 host address 0x001c
    	NS authoritative name server 0x0002
    	CNAME alias canonical name 0x0005
    	SOA start of zone authority 0x0006
    	PTR Domain name pointer 0x000c
    	HINFO host info 0x000d
    	MINFO mailbox/mail list info 0x000e
    	MX mail exchange 0x000f
    	AXFR zone transfer 0x00fc 
    */

    if (mode == DNS_MODE_ANSWER) {
        /* Default flags for a standard query (0x8580) */
	/* Shall it be authoritative answer... or not ? :) */

        //response[0] = 0x81;
        response[0] = 0x85;
        response[1] = 0x80;
        response+=2;
        /* Questions 1 */
        response[0] = 0x00;
        response[1] = 0x01;
        response+=2;
        /* Answers 1 */
        response[0] = 0x00;
        response[1] = 0x01;
        response+=2;
        if (EXT_DEBUG) { printf(" *** EXITING MODE_ANSWER\n"); }
    
    } else if (mode == DNS_MODE_ERROR) {
        
	/* DNS_MODE_ERROR should truncate message instead of building it up ... 
	 * Server failure (0x8182), but what if we wanted an NXDOMAIN (0x....) ?
	 * Being DNSP still under test, we do not care much. Nobody likes failures */
	    
	/*
	     * NOERROR (RCODE:0) : DNS Query completed successfully
	     * FORMERR (RCODE:1) : DNS Query Format Error
	     * SERVFAIL (RCODE:2) : Server failed to complete the DNS request
	     * NXDOMAIN (RCODE:3) : Domain name does not exist
	     * NOTIMP (RCODE:4) : Function not implemented
	     * REFUSED (RCODE:5) : The server refused to answer for the query
	     * YXDOMAIN (RCODE:6) : Name that should not exist, does exist
	     * XRRSET (RCODE:7) : RRset that should not exist, does exist
	     * NOTAUTH (RCODE:9) : Server not authoritative for the zone
	     * NOTZONE (RCODE:10) : Name not in zone
	     * 11-15           available for assignment
	     * 16    BADVERS   Bad OPT Version             
	     * 16    BADSIG    TSIG Signature Failure      
	     * 17    BADKEY    Key not recognized          
	     * 18    BADTIME   Signature out of time window
	     * 19    BADMODE   Bad TKEY Mode               
	     * 20    BADNAME   Duplicate key name          
	     * 21    BADALG    Algorithm not supported     
	     * 22-3840         available for assignment
	     *   0x0016-0x0F00
	     * 3841-4095       Private Use
	     *   0x0F01-0x0FFF
	     * 4096-65535      available for assignment
	     *   0x1000-0xFFFF
	*/

        response[0] = 0x81;
        response[1] = 0x82;
        response+=2;
        /* Questions 1 */
        response[0] = 0x00;
        response[1] = 0x01;
        response+=2;
        /* Answers 0 */
        response[0] = 0x00;
        response[1] = 0x00;
        response+=2;

	/* Are we into "No such name" ?... just an NXDOMAIN ?? */ 
	//*response++ = 0x00;
        if (EXT_DEBUG) { printf(" *** EXITING MODE_ERROR\n"); }
    }
    
    /* Authority RRs 0 */
    /* authorities can be worked out and be present. As scope of DNSP was to 
     * minimise answers ... this part is lagging/queued */
    response[0] = 0x00;
    response[1] = 0x00;
    response+=2;
    
    /* Additional RRs 0 */
    /* as authority section, same comment */
    response[0] = 0x00;
    response[1] = 0x00;
    response+=2;

    if (DNSDUMP) { hexdump(response_ptr, response - response_ptr + 2); }

    /* Query */
    strncat(response, dns_req->query, dns_req->hostname_len);
    response+=dns_req->hostname_len+1;
    
    /* Type */
    response[0] = (uint8_t)(dns_req->qtype >> 8);
    response[1] = (uint8_t)dns_req->qtype;
    response+=2;
    
    /* Class */
    response[0] = (uint8_t)(dns_req->qclass >> 8);
    response[1] = (uint8_t)dns_req->qclass;
    response+=2;

    /* Answer */
    if (mode == DNS_MODE_ANSWER) {
        /* Pointer to host name in query section */
        response[0] = 0xc0;
        response[1] = 0x0c;
        response+=2;
        
	if (dns_req->qtype == 0x0f) {
		// MX
        	response[0] = 0x00;
	        response[1] = 0x0f;
        	response+=2;
	} else if (dns_req->qtype == 0xFF) {
		// ALL
        	response[0] = 0x00;
	        response[1] = 0xFF;
        	response+=2;
	} else if (dns_req->qtype == 0x01) {
		// A
		*response++ = 0x00;
		*response++ = 0x01;
	} else if (dns_req->qtype == 0x05) {
		// CNAME
        	response[0] = 0x00;
	        response[1] = 0x05;
        	response+=2;
	} else if (dns_req->qtype == 0x0c) {
		// PTR
        	response[0] = 0x00;
	        response[1] = 0x0c;
        	response+=2;
	} else if (dns_req->qtype == 0x02) {
		// NS
        	response[0] = 0x00;
	        response[1] = 0x02;
        	response+=2;
	} else {
        	printf(" *** NO PARSE HAPPENED\n");
		return;
		//*response++ = 0x00;
		//*response++ = 0x01;
	}
        
        /* Class IN */
	/* other classes to be supported, not sure is WANTED but shall be implemented for compatibility */
	*response++ = 0x00;
	*response++ = 0x01;

       	/* TTL (4 hours to begin with, recently added thread callback, missing only HTTP interpretation of header, correctly generated on PHP) */
	/* 0000: Cache-control: public, max-age=276, s-maxage=276 */

	long int decimalNumber,remainder,quotient;
	int i=1,j,temp;
	char hex[5];
	unsigned char buf[4];

	quotient = ttl;

        //printf(" *** TTL SET\n");
	/* I still have issues in HEX/INT/CHAR conversions ... please help !! */
	
	//while(quotient!=0) {
	while(quotient!=1) {
	  if (quotient <10) break;
	  temp = quotient % 16;
	  
	  //To convert integer into character
	  if( temp < 10) {
	    temp = temp + 48;
	  } else {
	    temp = temp + 55;
	  }

	  quotient = quotient / 16;

	  if (EXT_DEBUG) { printf("\tTemp    : %u, %2x\n",temp,temp); }
	  
	  //sprintf(response++,"%x",temp);

	  /*
	  response[0] = quotient;
	  response++;
	  */

	  //*response++ = temp;
	  //response+=1;
	  
	  if (EXT_DEBUG) { printf("\tQuotient: %u, %2x\n",quotient,quotient); }
	  
	  //hex[i++]= temp;
	  //printf("QQQ: %x",temp);
	  
	  //if (temp = 0) break;
	  
	  //sprintf(hex,"%x",quotient);
	  //*response++= puts(hex);
	  //puts(response++);
	  //sprintf(response++,"%x",quotient);
	  //response[0]+= quotient;
	  //sprintf(response++, "0x%x", (((unsigned)hex[0])<<16)+(((unsigned)hex[1])<<8)+(unsigned)hex[2]);

	  //if (DNSDUMP) { generic_print(be32(buf, hex), sizeof buf); }
	}
	
	for (j = i -1 ;j> 0;j--)
	        printf("%c\n",hex[j]);
	//return 0;

	int a[25],c=0,x;
	int dec = ttl;

	while(dec>0) {
		if (dec < 10) break;
		a[c]=dec%16;
		response[0] = a[c];
		response++;
		dec=dec/16;
		c++;
	}

	//sprintf(response++,"%x",c);
	//if (DNSDUMP) { printf(" *** HEXA PRE-CONVERSION: %d\n",c); }
	for(x=c-1;x>=0;x--) {
		if(a[x]>=10) {
			printf("%c",a[x]+55);
		} else {
			printf("%d",a[x]);
		}
		//sprintf(response++,"%x",c);
		/* recover this ... */
		//response+= c;
	}
	printf("\n");
	//*response++= sprintf(hex,"%x",quotient);
	
	//if (DNSDUMP) { printf(" *** HEXA POST-CONVERSION: %d\n",c); }
	//printf("----DECIMAL Q: %lu\n",quotient);

	/* If you are a bit acquainted with hex you dont need to convert to binary. */
	/* Just take the base-16 complement of each digit, and add 1 to the result. */
	/* So you get 0C5E. Add 1 and here's your result: 0C5F. */

	/* for a faster approach you can also flip the bits left to very first set bit and find out the 2s complement */

	/* (instead of finding 1ns and then adding 1 to it) 
	 * 1111 0011 1010 0001 toggle the bits left to first set bit
	 * 0000 1100 0101 1111
	 *
	 * i expect you would like this if bit pattern is changed to binary than hex :)
	*/
	
	/*
	*response+= sprintf(hex,"%x",quotient);
	*response++= sprintf(hex,"%x",quotient);
	sprintf(response++,"%x",ttl);
	printf("TTL HEX: %x\n",ttl);
	printf("len HEX: %d\n",sizeof(ttl));
	*/
	
	/* The TTL was always kept in mind in DNSP development, but mostly faked for reason of simplicity. */
	/* With the advent of DNS-over-HTTP drafts, the need became more stringent, and here we go ! */
	/* IIRC, this is 14400, 4 hours very optimistic */
	
	/*
	*response++ = 0x00;
	*response++ = 0x00;
	*response++ = 0x38;
	*response++ = 0x40;
	*/

	/*
	for (j = i -1 ;j> 0;j--)
	    //printf("%c",hexadecimalNumber[j]);
	    response = hexadecimalNumber[j];
	return 0;
	*/
	
	/* 0x08 - backspace \010 octal, 0x09 - horizontal tab, 0x0a - linefeed, 0x0b - vertical tab \013 octal, 0x0c - form feed, 0x0d - carriage return, 0x20 - space */ 
	
	/* DNS request TYPE parsing */
	if (dns_req->qtype == 0x0c) {
        	// PTR
	        /* Data length (4 bytes)*/
	        response[0] = 0x00;
	        response[1] = 0x04;
	        response+=2;
		response[0] = 0xc0;
		response[1] = 0x0c;
	       	response+=2;

	} else if (dns_req->qtype == 0x02) { 
		// NS
	        response[0] = 0x00;
		response[1] = (strlen(ip)-1);
        	response+=2;

		pch = strtok((char *)ip,". \r\n\t");

		while (pch != NULL)
		{
			ppch = strlen(pch);
			*response++ = strlen(pch);
			for (i = 0; i < strlen(pch); ++i) {
				*response++ = pch[i];
				maxim[i] = pch[i];
			}

    			pch = strtok(NULL, ". ");
			
			//if (pch != ' ' && pch != '\t' && pch != NULL) {
			//if (pch == ' ' || pch == '\t' || pch == NULL || pch == '\n' || pch == '\r') {
			if (pch == NULL) {
				for (i = 0; i < ppch+1; ++i) {
					response--;
				}
                                *response++ = ppch-3;
				for (i = 0; i < ppch-3; ++i) {
        	                	*response++ = maxim[i];
                	        }
				
			}
		}

		*response++ = 0x00;

	} else if (dns_req->qtype == 0x05) {
	       	// CNAME
        	response[0] = 0x00;
		response[1] = (strlen(ip)-1);
        	response+=2;

		pch = strtok((char *)ip,". \r\n\t");

		while (pch != NULL)
		{
			ppch = strlen(pch);
			*response++ = strlen(pch);
			for (i = 0; i < strlen(pch); ++i) {
				*response++ = pch[i];
				maxim[i] = pch[i];
			}

    			pch = strtok (NULL, ". ");
			
			if (pch == NULL) {
				for (i = 0; i < ppch+1; ++i) {
					response--;
				}
                                *response++ = ppch-3;
	                        for (i = 0; i < ppch-3; ++i) {
        	                	*response++ = maxim[i];
                	        }
			}
			
		}

		*response++ = 0x00;

	} else if (dns_req->qtype == 0x0f) {
	       	//MX RECORD
	        /* Data length accounting for answer plus final dot and termination field */
        	response[0] = 0x00;
		response[1] = (strlen(ip)+3);
        	response+=2;

	        /* PRIO (4 bytes)*/
		response[0] = 0x00;
		response[1] = 0x0a;
        	response+=2;

	        /* POINTER, IF YOU ARE SO BRAVE OR ABLE TO USE IT (4 bytes) -> do not use label-mode then...
		 * in that case, you should re-write the code to have super-duper minimal responses.
		 * That code would also need to implement domain comparison to check if suffix can be appended */

		//response[0] = 0xc0;
		//response[1] = 0x0c;
        	//response+=2;

		pch = strtok((char *)ip,".\r\n\t");
		while (pch != NULL)
		{
			//maxim = NULL;
			ppch = strlen(pch);
			*response++ = strlen(pch);
			for (i = 0; i < strlen(pch); ++i) {
				*response++ = pch[i];
				//maxim[0] += 0x00;
				maxim[i] = pch[i];
			}
			//strcat(response, pch);
			//*response++ = *maxim;
		        
    			pch = strtok (NULL, ".");
			if (pch == NULL) {
				for (i = 0; i < ppch+1; ++i) {
					response--;
				}
                                *response++ = ppch-1;
	                        for (i = 0; i < ppch-1; ++i) {
        	                	*response++ = maxim[i];
                	        }
			}
		}

		*response++ = 0x00;
		
	} else if (dns_req->qtype == 0x01) {
	        // A

	        /* Data length (4 bytes)*/
		*response++ = 0x00;
		*response++ = 0x04;

        	token = strtok((char *)ip,".");
        	if (token != NULL) response[0] = atoi(token);
        	else return;

        	token = strtok(NULL,".");
        	if (token != NULL) response[1] = atoi(token);
        	else return;

        	token = strtok(NULL,".");
        	if (token != NULL) response[2] = atoi(token);
        	else return;

        	token = strtok(NULL,".");
        	if (token != NULL) response[3] = atoi(token);
        	else return;

		response+=4;
		
      	} else {
        	fprintf(stdout, "DNS_MODE_ISSUE, no headers to parse !\n");
		//return;
	}
	
	//*response++=(unsigned char)(strlen(ip)+1);
	//memcpy(response,ip,strlen(ip)-1);
	//strncpy(response,ip,strlen(ip)-1);
	
	/* example kept for educational purposes, to show how the request packet is parsed. Here is what you receive on a 'strace' */
	//recvfrom(3, "\326`\1 \0\1\0\0\0\0\0\1\6google\2it\0\0\1\0\1\0\0)\20\0"..., 256, 0, {sa_family=AF_INET, sin_port=htons(48379), sin_addr=inet_addr("192.168.2.84")}, [16]) = 38
	//(3, "\24\0\0\0\26\0\1\3\23\306;U\0\0\0\0\0\0\0\0", 20, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 20
	//(3, "z\271\205\200\0\1\0\1\0\0\0\0\6google\2hr\0\0\2\0\1\300\f\0\2\0"..., 41, 0, {sa_family=0x1a70 /* AF_??? */, sa_data="s\334\376\177\0\0\20D\1\270\223\177\0\0"}, 8)
	
    	if (EXT_DEBUG) { printf(" *** ASSOCIATE RESPONSE TO CLIENT\n"); }
	//(struct sockaddr *)xclient->sin_family = AF_INET;
	int yclient_len = sizeof(yclient);
        yclient->sin_family = AF_INET;
	//yclient->sin_addr.s_addr = inet_addr("192.168.2.84"); // initial tests, my year of birth is 1984
	//yclient->sin_port = htons(yclient->sin_port);
	yclient->sin_port = yclient->sin_port;
	memset(&(yclient->sin_zero), 0, sizeof(yclient->sin_zero)); // zero the rest of the struct 
	//memset(yclient, 0, 0);

    	if (DEBUG) {
	  printf("INSIDE-dns-req->hostname		: %s\n", dns_req->hostname);
	  printf("INSIDE-xrequestlen			: %u\n", (uint16_t)xrequestlen);
	  printf("INSIDE-yclient->sin_addr.s_addr        	: %u\n", (uint32_t)(yclient->sin_addr).s_addr);
	  printf("INSIDE-yclient->sin_port-htons		: %u\n", htons(yclient->sin_port));
	  printf("INSIDE-yclient->sin_port               	: %u\n", (uint32_t)(yclient->sin_port));
	  printf("INSIDE-yclient->sin_family		: %d\n", (uint32_t)(yclient->sin_family));
	}
        
	/* example kept for educational purposes, to show how the response packet is built, tailored for the client */
	/* here is what you send back */
	//bytes_sent = sendto(3, "\270\204\205\200\0\1\0\1\0\0\0\0\6google\2jp\0\0\1\0\1\300\f\0\1\0"..., 43, 0, {sa_family=0x0002 /* AF_??? */, sa_data="\365\366\374\177\0\0\1\0\0\0\3\0\0\0"}, 16)
		
	/* save HEX packet structure to file, i.e. for feeding caches, or directly serve HTTP content from the same daemon */
	/*
        #define MAX_LENGTH 512
        FILE *fout = fopen("out.txt", "w");
    
        if(ferror(fout)) {
            fprintf(stderr, "Error opening output file");
            return 1;
        }
        char init_line[]  = {"char hex_array[] = { "};
        const int offset_length = strlen(init_line);
    
        char offset_spc[offset_length];
    
        unsigned char buff[1024];
        char curr_out[1024];
        //char curr_out[64];
    
        int count, i;
        int line_length = 0;
    
        memset((void*)offset_spc, (char)32, sizeof(char) * offset_length - 1);
        offset_spc[offset_length - 1] = '\0';
    
        fprintf(fout, "%s", init_line);
    
	// NOT USEFUL TO USE A WHILE-LOOP (got from CURLLIB examples)
        //while(!feof(stdin))
        //{
            //count = fread(buff, sizeof(char), sizeof(buff) / sizeof(char), stdin);
        	count = sizeof(response);
    
            for(i = 0; i < count; i++)
            {
                line_length += sprintf(curr_out, "%#x, ", buff[i]);
    
                fprintf(fout, "%s", curr_out);
                if(line_length >= MAX_LENGTH - offset_length)
                {
                    fprintf(fout, "\n%s", offset_spc);
                    line_length = 0;
                }
            }
        //}
	
        fseek(fout, -2, SEEK_CUR);
        fprintf(fout, " };\n");
        fclose(fout);
	*/

        /* TCP length header re-stamp */
	if (protoq == 1) {
	  int resulttt = 0;
	  int resulqqq = 0;
	  int resultq = 0;

	  //finalresponse[0] = (uint8_t)(sizeof(&response) >> 8);
	  //finalresponse[0] = (uint8_t)(yclient_len >> 8);
	  //finalresponse[0] = (uint8_t)((sizeof(response) - sizeof(response_ptr)) >> 8);
	  //finalresponse[0] = (uint8_t)(sizeof(yclient) >> 8);
	  //finalresponse+=sizeof(response_ptr);
          //finalresponse+=2;

	  /* experimental fix to allow testing autosize TCP */
	  int norm2 = (dns_req->tcp_size + sizeof(response_ptr) - 5);
	  printf("%d artificial bytes\n",norm2);
	  //int norm2 = (dns_req->tcp_size + finalresponse - finalresponse_ptr + sizeof(response_ptr));
	  finalresponse[0] = (uint8_t)(norm2 >> 8);
	  finalresponse[1] = (uint8_t)norm2;
          //finalresponse[0] = 0x00;
          //finalresponse[1] = 0x35; // testing with 55 bytes responses, as for A news.infomaniak.com
          //finalresponse+=2;
          //finalresponse+=sizeof(response)+2;
	  //finalresponse[sizeof(&response)];
	  //copy_string(*finalresponse,*response);
          //finalresponse+=sizeof(response);
	  
	  //strcat(finalresponse, &response);
	  //strncat(finalresponse, dns_req->tcp_size, 2);
	  //strncat(finalresponse, response_ptr, sizeof(response_ptr));
	  //finalresponse+=2;

	  /* start off 3rd byte to leave the overwritten tcp_size value intact */
	  for (int i=2; i< (sizeof(response_ptr) + 2); i++) {
	      resulttt <<= 8;
	      resulttt |= response_ptr[i];
              finalresponse[i] = resulttt;
              //*finalresponse++ = resulttt;
	      resulqqq++;
	      //finalresponse+=sizeof(resulttt);
	  }
	  
	  finalresponse+=sizeof(resulqqq);

	  /*
	  for (int t=2; i< (sizeof(dns_req->qtype) + 2); t++) {
	      resulttt <<= 8;
	      resulttt |= response_ptr[t];
              finalresponse[t] = resulttt;
              *finalresponse++ = resulttt;
	      resultq++;
	      //finalresponse+=sizeof(resulttt);
	  }
	  */
	  
	  //finalresponse+=sizeof(resultq);
	  //finalresponse+=resulqqq;
	  //finalresponse+=sizeof(yclient);

	  //finalresponse+=sizeof(response_ptr)+2;
          //*finalresponse++ = &response_ptr;

	  //while(*finalresponse++ = *response++);
	  
	  //*finalresponse++ = &response;
          //finalresponse += sizeof(response);
	  
	  //*finalresponse++ = &response_ptr;
	  //finalresponse += sizeof(&response - &response_ptr);

          if (DNSDUMP) { 
	    printf(" *** finalresponse_ptr, finalresponse + 6 - finalresponse_ptr\n"); 
	    hexdump(finalresponse_ptr, finalresponse + 6 - finalresponse_ptr);
            printf(" *** finalresponse_ptr, finalresponse + 2 - finalresponse_ptr\n");
	    hexdump(finalresponse_ptr, finalresponse + 2 - finalresponse_ptr);
            printf(" *** finalresponse_ptr, finalresponse - finalresponse_ptr\n");
	    hexdump(finalresponse_ptr, finalresponse - finalresponse_ptr);
            printf(" *** finalresponse_ptr, response + 2 - response_ptr\n");
	    hexdump(finalresponse_ptr, response + 2 - response_ptr);
	  }

	  if (DEBUG) { printf("SENT %d bytes of finalresponse\n\n", finalresponse - finalresponse_ptr); }
	  if (DEBUG) { printf("SENT %d bytes of response (including +2 for TCP)\n", response - response_ptr); }
        }

	/* dump to udpwireformat */
	if (DNSDUMP) {
	  printf(" *** response_ptr, response - response_ptr\n"); 
	  hexdump(response_ptr, response - response_ptr);
	}

	/* send it back, onto the same socket. we allow for independent threds, see other notes about the topic */
        if (protoq == 1) {
	  //printf("sending TCP resp\n");
	  bytes_sent = sendto(sd, response_ptr, response - response_ptr, MSG_DONTWAIT, (struct sockaddr *)yclient, sizeof(yclient));
	  //bytes_sent = sendto(sd, response_ptr, response - response_ptr, MSG_WAITALL, (struct sockaddr *)(&yclient), 16);
	} else {
	  //printf("sending UDP resp\n");
          bytes_sent = sendto(sd, response_ptr, response - response_ptr, MSG_DONTWAIT, (struct sockaddr *)yclient, 16);
	}
    
    } else if (mode == DNS_MODE_ERROR) {

        if (EXT_DEBUG) { fprintf(stdout, "DNS_MODE_ERROR\n"); }
	//(struct sockaddr *)xclient->sin_family = AF_INET;
	int yclient_len = sizeof(yclient);

	/* few lines left for reference, useful to understand sin_addr and sin_port struct */
	//yclient->sin_addr.s_addr = inet_addr("192.168.2.84"); 
	//yclient->sin_port = htons(yclient->sin_port);
        yclient->sin_family = AF_INET;
	yclient->sin_port = yclient->sin_port;
	memset(&(yclient->sin_zero), 0, sizeof(yclient->sin_zero)); // zero the rest of the struct 
	//memset(yclient, 0, 0);
	if (DNSDUMP) {
	  hexdump(response_ptr, response - response_ptr);
	  printf(" *** response_ptr, response - response_ptr\n"); 
	}

        if (protoq == 1) {
	  printf("sending TCP resp\n");
	  bytes_sent = sendto(sd, response_ptr, response - response_ptr, MSG_DONTWAIT, (struct sockaddr *)yclient, 16);
	} else {
	  printf("sending UDP resp\n");
          bytes_sent = sendto(sd, response_ptr, response - response_ptr, MSG_DONTWAIT, (struct sockaddr *)yclient, 16);
	}

    } else {
        fprintf(stdout, "DNS_MODE_UNKNOWN\n");
	if (DNSDUMP) { hexdump(response_ptr, response - response_ptr); }

        if (protoq == 1) {
	  //bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)yclient, 16);
	  bytes_sent = sendto(sd, response_ptr, response - response_ptr + 2, MSG_DONTWAIT, (struct sockaddr *)(&yclient), sizeof(yclient));
	} else {
          //bytes_sent = sendto(sd, response_ptr, response - response_ptr, MSG_DONTWAIT, (struct sockaddr *)yclient, 16);
          bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)yclient, 16);
          //bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)yclient, 16);
	}
    }

    /* DNS VOLUME DISPLAY, UDP and TCP */
    if (DEBUG) { printf("SENT %d bytes\n", (uint32_t)bytes_sent); }
    
    /* that sync/datasync slows down, and honestly is not needed when having no disk access or very very big sockets/queues .. */
    fdatasync(sd);

    close(sd);
    free(response_ptr);
    free(dns_req);
    //free(ip);
}

/* homemade substingy func */
char *substring(char *string, int position, int length) {
   char *pointer;
   int c;
 
   pointer = malloc(length+1);
   
   /* 0x09 - horizontal tab, 0x0a - linefeed, 0x0b - vertical tab, 0x0c - form feed, 0x0d - carriage return, 0x20 - space */
 
   if (pointer == NULL)
   {
      printf("Unable to allocate memory.\n");
      exit(1);
   }
 
   for (c = 0 ; c < length ; c++)
   {
      *(pointer+c) = *(string+position-1);      
      string++;   
   }
 
   *(pointer+c) = '\0';
 
   return pointer;
}
 
/* struct to support libCurl callback */
struct MemoryStruct {
  char *memory;
  size_t size;
};
 
/* new libCurl callback */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) { /* out of memory! */ printf("not enough memory (realloc returned NULL)\n"); return 0; }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

/* libCurl write data callback */
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream) {
  size_t stream_size;
  stream_size = size * nmemb + 1;
  bzero(stream, HTTP_RESPONSE_SIZE);
  memcpy(stream, ptr, stream_size);
  printf("%s\n",stream);
  //printf(substring(stream,31,5));
  return stream_size-1;
}

/* handler checker/limiter */
static int hnd2num(CURL *ch) {
  int i;
  for(i = 0; i< num_transfers; i++) {
    if(curl_hnd[i] == ch)
      return i;
  }
  /* weird, but just a fail-safe */ 
  return 0;
}

static void dump(const char *text, int num, unsigned char *ptr, size_t size, char nohex) {
  size_t i;
  size_t c;
 
  unsigned int width = 0x10;
 
  if(nohex)
    /* without the hex output, we can fit more on screen */ 
    width = 0x40;
 
  fprintf(stderr, "%d %s, %ld bytes (0x%lx)\n",
          num, text, (long)size, (long)size);
 
  for(i = 0; i<size; i += width) {
 
    fprintf(stderr, "%4.4lx: ", (long)i);
 
    if(!nohex) {
      /* hex not disabled, show it */ 
      for(c = 0; c < width; c++)
        if(i + c < size)
          fprintf(stderr, "%02x ", ptr[i + c]);
        else
          fputs("   ", stderr);
    }
 
    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */ 
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stderr, "%c",
              (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */ 
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stderr); /* newline */ 
  }
}

static size_t header_handler(void *ptr, size_t size, size_t nmemb, void *userdata) {
    char *x = calloc(size + 1, nmemb);
    assert(x);
    memcpy(x, ptr, size * nmemb);
    printf("New header:\n%s\n", x);
    return size * nmemb;
}

/*
pub struct curl_fileinfo {
    pub filename: *mut c_char,
    pub filetype: curlfiletype,
    pub time: time_t,
    pub perm: c_uint,
    pub uid: c_int,
    pub gid: c_int,
    pub size: curl_off_t,
    pub hardlinks: c_long,
    pub strings_time: *mut c_char,
    pub strings_perm: *mut c_char,
    pub strings_user: *mut c_char,
    pub strings_group: *mut c_char,
    pub strings_target: *mut c_char,
    pub flags: c_uint,
    pub b_data: *mut c_char,
    pub b_size: size_t,
    pub b_used: size_t,
}
*/

/* BEWARE: libcurl does not unfold HTTP "folded headers" (deprecated since RFC 7230). */
/* A folded header is a header that continues on a subsequent line and starts with a whitespace. */
/* Such folds will be passed to the header callback as a separate one, although strictly it is just a continuation of the previous line. */
/* A complete HTTP header that is passed to this function can be up to CURL_MAX_HTTP_HEADER (100K) bytes. */
static int my_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp) {
  const char *text;
  int num = hnd2num(handle);
  (void)handle; /* prevent compiler warning */ 
  (void)userp;
  switch(type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== %d Info: %s", num, data);
    /* FALLTHROUGH */ 
  default: /* in case a new one is introduced to shock us */ 
    return 0;
 
  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    printf("-----\n");
    /* Parsing header as tokens, find "cache-control" and extract TTL validity */
    //char** tokens;
    char *compare;
    char ref[14];
    compare = substring(data, 1, 13);
    strcpy(ref, "cache-control");
    int cacheheaderfound = strcmp(compare,ref);
    //dump(text, num, (unsigned char *)data, size, 1);

    if(cacheheaderfound == 0) {
    	dump(text, num, (unsigned char *)data, size, 0);
     
    	/* More general pattern */
    	const char *my_str_literal = data;
    	char *token, *str, *tofree;
    	
    	tofree = str = strdup(my_str_literal);  // We own str's memory now.
    	while ((token = strsep(&str, ","))) printf(" ----> %s\n",token);
    	free(tofree);
    	//printf(" -> %s", data);
	/*
    	tokens = str_split(data, ',');
    	if (tokens != NULL)
    	{
    	    int i;
    	    for (i = 0; *(tokens + i); i++)
    	    {
    	        //printf("%s\n", *(tokens + i));
    	        free(*(tokens + i));
    	    }
    	    free(tokens);
	    ref == NULL;
	    //return 0;
    	}
	*/
    }
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }
 
  return 0;
}

static void setup(CURL *hnd, char *script_target) {
  FILE *out; // = fopen(OUTPUTFILE, "wb");
  int num = 1;
  //char *q = ( char * ) malloc( 512 * sizeof( char ) );
  char q[512];
  char filename[128];
  
  snprintf(filename, 128, "dl-%d", num);
  out = fopen(filename, "wb");
  /* write to this file, will be served via HTTP/2 */ 
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, out);
  /* we shall avoid hardcoding: URL will become a CLI parameter (or a static list, for universal double blind root-check) */
  /* with parallel threads/verification possible */ 
  snprintf(q, sizeof(q)-1, "https://php-dns.appspot.com/%s", script_target);

  curl_easy_setopt(hnd, CURLOPT_URL, q);
  fprintf(stderr, "%s\n", q);
 
  if (DEBUGCURL) { curl_easy_setopt(hnd, CURLOPT_VERBOSE,  1); } else { curl_easy_setopt(hnd, CURLOPT_VERBOSE,  0); }

  curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, my_trace);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
 
  //curl_easy_setopt(hnd, CURLOPT_SSLCERT, "client.pem"); //curl_easy_setopt(hnd, CURLOPT_SSLKEY, "key.pem"); //curl_easy_setopt(hnd, CURLOPT_KEYPASSWD, "s3cret")
  curl_easy_setopt(hnd, CURLOPT_CAPATH, "/usr/share/ca-certificates/mozilla");
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 2L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 2L);
  /* OCSP not always available on clouds */
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYSTATUS, 0L);
 
  #if (CURLPIPE_MULTIPLEX > 0)
    /* wait for pipe connection to confirm */ 
    curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);
  #endif
 
  /* placeholder, can parallelise N threads but is blocking/waiting. About the interest of spawning multiple/multipath things */
  //curl_hnd[num] = hnd;
}

/* called when there's an incoming push */ 
static int server_push_callback(CURL *parent, CURL *easy, size_t num_headers, struct curl_pushheaders *headers, void *userp) {
  char *headp;
  size_t i;
  int *transfers = (int *)userp;
  char filename[128];
  FILE *out;
  static unsigned int count = 0;
 
  (void)parent; /* we have no use for this */ 
 
  snprintf(filename, 128, "push%u", count++);
  /* here's a new stream, save it in a new file for each new push */ 
  out = fopen(filename, "wb");
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, out);
 
  fprintf(stderr, "**** push callback approves stream %u, got %d headers!\n", count, (int)num_headers);
 
  for(i = 0; i<num_headers; i++) {
    headp = curl_pushheader_bynum(headers, i);
    fprintf(stderr, "**** header %u: %s\n", (int)i, headp);
  }
 
  headp = curl_pushheader_byname(headers, ":path");
  if(headp) {
    fprintf(stderr, "**** The PATH is %s\n", headp /* skip :path + colon */ );
  }
 
  /* one more */ 
  (*transfers)++;
  return CURL_PUSH_OK;
}

/* Hostname lookup -> OK: Resolved IP, KO: Null */
char *lookup_host(const char *host, const char *proxy_host, unsigned int proxy_port, const char *proxy_user, const char *proxy_pass, const char *lookup_script, const char *typeq, unsigned int wport) {
  CURL *ch;
  CURL *hnd;
  //CURL *easy;					// for CURLM and parallel
  //CURL *easy[NUM_HANDLES];
  //CURLcode res;				// for CURLE error report
  //CURLSH *shobject = curl_share_init();
  //CURLSH *curlsh;
  //CURLM *multi_handle;

  /* keep number of running handles */ 
  int still_running;
  /* we start with one */ 
  int transfers = 1;

  int i;
  int ret;

  char *http_response,
       *script_url,
       *script_get,
       *pointer;
  char base[2];

  /* CURL structs, different needs/interfaces */
  //struct curl_slist *hosting = NULL;
  //struct curl_slist *list = NULL;
  struct curl_slist *list;
  struct curl_slist *slist1;

  struct CURLMsg *m;

  /* hold result in memory */
  //struct MemoryStruct chunk;
  //chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */ 
  //chunk.size = 0;    /* no data at this point */ 

  script_url = malloc(URL_SIZE);
  http_response = malloc(HTTP_RESPONSE_SIZE);
  bzero(script_url, URL_SIZE);
  
  //char *n = ( char * ) malloc( 80 * sizeof( char ) );
  char n[512];

  /* here my first format, HOST+QTYPE, but many others including DNS-over-HTTP or GoogleDNS can be integrated */
  snprintf(script_url, URL_SIZE-1, "%s?host=%s&type=%s", lookup_script, host, typeq);
  snprintf(n, sizeof(n)-1, "?host=%s&type=%s", host, typeq); // CLUSTER

  /* Beware of bloody proxy-string, not any format accepted, CURL is gentle if failing due to proxy */
  //snprintf(proxy_url, URL_SIZE-1, "http://%s/", proxy_host);
  //if (proxy_host != NULL) { fprintf(stderr, "Required substring is \"%s\"\n", proxy_url); }

  /* HTTPS DETECTION CODE ... might be better :) */
  pointer = substring(script_url, 5, 1);
  strcpy(base, "s");

  int result = strcmp(pointer, base);
  //printf("Required substring is \"%s\"\n", pointer);
  //printf("Compared substring is \"%s\"\n", base);
  //printf("Result is \"%d\"\n", result);

  if(result == 0) {
          wport=443;
  } else {
          printf(" *** HTTP does NOT guarantee against MITM attacks. Consider switching to HTTPS webservice\n");
          wport=80;
  }

  free(pointer);

  /* do that many transfers */ 
  num_transfers = 1;

  //if(!num_transfers || (num_transfers > NUM_HANDLES))
  //num_transfers = 3; /* a suitable low default */ 

  /* init a multi stack */ 
  //multi_handle = curl_multi_init();

  /* curl setup */
  /* read: https://curl.haxx.se/libcurl/c/threadsafe.html */
  /* to implement sharing and locks between threads */

  ch = curl_easy_init();

  /*
      CURLOPT_MAXREDIRS, 2
      CURLOPT_COOKIEJAR, "cookies.txt"
      CURLOPT_COOKIEFILE, "cookies.txt"
  //curl_setopt($ch, CURLOPT_COOKIE, "");
  //curl_setopt($ch, CURLOPT_POST, 1);
  //curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
  */

  /* set specific nifty options for multi handlers or none at all */

  /*
  easy = curl_easy_init();
  //setup(easy);
  //setup(easy, lookup_script);
  setup(easy, n);

  // add the easy transfer
  curl_multi_add_handle(multi_handle, easy);

  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi_handle, CURLMOPT_PUSHFUNCTION, server_push_callback);
  curl_multi_setopt(multi_handle, CURLMOPT_PUSHDATA, &transfers);
  */

  /* placeholder for DNS-over-HTTP (doh) POST method choice, to become a CLI parameter */
  //curl_setopt($ch,CURLOPT_POST,1);
  //curl_setopt($ch,CURLOPT_POSTFIELDS,'customer_id='.$cid.'&password='.$pass);

  //curl_setopt($ch, CURLOPT_HEADER, 1L);
  curl_easy_setopt(ch, CURLOPT_URL, script_url);
  curl_easy_setopt(ch, CURLOPT_PORT, wport); /* 80, 443 */

  /* HTTP/2 prohibits connection-specific header fields. The following header fields must not appear */
  /* “Connection”, “Keep-Alive”, “Proxy-Connection”, “Transfer-Encoding” and “Upgrade”.*/
  /* Additionally, “TE” header field must not include any value other than “trailers”.*/

  curl_easy_setopt(ch, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
  //curl_easy_setopt(ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  //curl_easy_setopt(ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  //curl_easy_setopt(ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  //curl_easy_setopt(ch, CURLOPT_SSL_ENABLE_ALPN, 1L);
  curl_easy_setopt(ch, CURLOPT_SSL_ENABLE_NPN, 1L);
  //curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
  //curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
  //curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);
  //curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT); //CURL_SSLVERSION_TLSv1
  //curl_easy_setopt(ch, CURLOPT_SSLENGINE, "dynamic");
  //curl_easy_setopt(ch, CURLOPT_SSLENGINE_DEFAULT, 1L);
  curl_easy_setopt(ch, CURLOPT_FILETIME, 1L);
  curl_easy_setopt(ch, CURLOPT_TCP_KEEPALIVE, 1L);

  /* Proxy common ports 1080 (generic proxy), 3128 (squid), 8118 (polipo again), 8888 (simplehttp2server), 9500, 1090 (socks) */
  curl_easy_setopt(ch, CURLOPT_PROXY, proxy_host);
  curl_easy_setopt(ch, CURLOPT_PROXYPORT, proxy_port);	
  curl_easy_setopt(ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);

  if ((proxy_user != NULL) && (proxy_pass != NULL)) {
      curl_easy_setopt(ch, CURLOPT_PROXYUSERNAME, proxy_user);
      curl_easy_setopt(ch, CURLOPT_PROXYPASSWORD, proxy_pass);
  }

  //curl_easy_setopt(ch, CURLOPT_MAXCONNECTS, MAXCONN);
  //curl_easy_setopt(ch, CURLOPT_FRESH_CONNECT, 0);
  //curl_easy_setopt(ch, CURLOPT_FORBID_REUSE, 0);
  //curl_setopt($curl, CURLOPT_AUTOREFERER, 1);

  /* send all data to this function */
  //curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, write_data);

  /* we pass our 'chunk' struct to the callback function */ 
  //curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(ch, CURLOPT_WRITEDATA, http_response);
  
  //curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, my_trace);
  
  /* cache with HTTP/1.1 304 "Not Modified" */
  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control

  // REQUEST
  /*
  Cache-Control: max-age=<seconds>
  Cache-Control: max-stale[=<seconds>]
  Cache-Control: min-fresh=<seconds>
  Cache-Control: no-cache 
  Cache-Control: no-store
  Cache-Control: no-transform
  Cache-Control: only-if-cached
  */
  // RESPONSE
  /*
  Cache-Control: must-revalidate
  Cache-Control: no-cache
  Cache-Control: no-store
  Cache-Control: no-transform
  Cache-Control: public
  Cache-Control: private
  Cache-Control: proxy-revalidate
  Cache-Control: max-age=<seconds>
  Cache-Control: s-maxage=<seconds>
  */
  // NON-STANDARD
  /*
  Cache-Control: immutable 
  Cache-Control: stale-while-revalidate=<seconds>
  Cache-Control: stale-if-error=<seconds>
  */

  /* H1 */
  // Cache-Control: public, max-age=276, s-maxage=276
  // Cache-control: public, max-age=276, s-maxage=276
  /* H2 */
  // cache-control: public, max-age=299, s-maxage=299

  /* set curlopt --> FOLLOW-LOCATION, necessary if getting 301 "Moved Permanently" */
  // reacting to // Location: http://www.example.org/index.asp
  //curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

  /* it doesnt cost much to verify, disable only while testing ! */
  curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 2L);
  curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 2L);;
  /* OCSP validation, avoided in the test phase, as some cloud including Google GCP do not provide it */
  /* Cloudflare CDN does well with terminated frontend-SSL certificate */
  curl_easy_setopt(ch, CURLOPT_SSL_VERIFYSTATUS, 0L);
  /* SSL engine config */
  //curl_easy_setopt(ch, CURLOPT_SSLCERT, "client.pem"); //curl_easy_setopt(ch, CURLOPT_SSLKEY, "key.pem"); //curl_easy_setopt(ch, CURLOPT_KEYPASSWD, "s3cret") 
  //static const char *pCertFile = "testcert.pem"; //static const char *pCACertFile="fantuznet.pem"; //static const char *pHeaderFile = "dumpit";
  //curl_easy_setopt(ch, CURLOPT_CAINFO, pCACertFile);
  //curl_easy_setopt(ch, CURLOPT_CAPATH, pCACertDir);
  //curl_easy_setopt(ch, CURLOPT_CAPATH, "/usr/share/ca-certificates/mozilla");
  //curl_easy_setopt(ch, CURLOPT_CAINFO, "/etc/ssl/certs/Comodo_AAA_Services_root.pem");

  /* Cloudflare is using COMODO CA */
  /* We shall avoid gzip as it clashes with OCSP validation .. */
  //curl_easy_setopt(ch, CURLOPT_ENCODING, "gzip, deflate, br, sdch");
  //curl_easy_setopt(ch, CURLOPT_ENCODING, "br");

  /* This timeout is deemed to become a parameter */
  curl_easy_setopt(ch, CURLOPT_TIMEOUT, 5);
  curl_easy_setopt(ch, CURLOPT_TCP_FASTOPEN, 1L);
  curl_easy_setopt(ch, CURLOPT_TCP_NODELAY, 0L);		/* disable Nagle with 0, for bigger packets (full MSS) */
  curl_easy_setopt(ch, CURLOPT_DNS_CACHE_TIMEOUT, 15);
  curl_easy_setopt(ch, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);	/* DNS CACHE WITHIN CURL, yes or not ? */
  curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);			/* No progress meter */
  curl_easy_setopt(ch, CURLOPT_BUFFERSIZE, 1024L);		/* lowering from 100K to 1K */

  if (DEBUGCURL) { curl_easy_setopt(ch, CURLOPT_VERBOSE,  1); } else { curl_easy_setopt(ch, CURLOPT_VERBOSE,  0); }

  /* wait for pipe to confirm */
  /*
  #if (CURLPIPE_MULTIPLEX > 0)
  	curl_easy_setopt(ch, CURLOPT_PIPEWAIT, 1L);
  #endif
  */

  /* do proxies like pipelining ? polipo yes, how about squid, nginx et al. ?? */
  /* anyway all the story changes completely with H2 and DOH specs */

  /* OVERRIDE RESOLVER --> add resolver CURL header, work in progress */
  // in the form of CLI --resolve my.site.com:80:1.2.3.4, -H "Host: my.site.com"

  /* OPTIONAL HEADERS, set with curl_slist_append */

  //list = curl_slist_append(list, "user-agent: nghttp2/1.21.90");
  //list = curl_slist_append(list, "User-Agent: curl/7.59.0-DEV");

  //hosting = curl_slist_append(hosting, "www.fantuz.net:80:217.114.216.51");
  //curl_easy_setopt(ch, CURLOPT_RESOLVE, hosting);
  //list = curl_slist_append(list, ":host:www.fantuz.net");
  
  list = curl_slist_append(list, "content-type: application/dns-udpwireformat");
  //curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/x-www-form-urlencoded; charset=UTF-8"]); // change to DNS type

  //list = curl_slist_append(list, "Request URL: http://www.fantuz.net/nslookup-doh.php?host=news.google.fr.&type=A");
  //list = curl_slist_append(list, "Request URL: http://www.fantuz.net/nslookup-doh.php");
  //list = curl_slist_append(list, "Request Method:GET");
  //list = curl_slist_append(list, "Remote Address: 217.114.216.51:443");
  //list = curl_slist_append(list, "Cache-Control:max-age=300");
  //list = curl_slist_append(list, "Connection:keep-alive");
  //list = curl_slist_append(list, "If-None-Match: *");

  /* Upgrades, not always a good idea */
  /*
  list = curl_slist_append(list, "Connection: Upgrade, HTTP2-Settings");
  list = curl_slist_append(list, "Upgrade: h2c");
  list = curl_slist_append(list, "HTTP2-Settings: AAMAAABkAAQAAP__");
  */

  /* Defining which one to use, between: gzip, deflate, br, sdch */
  //list = curl_slist_append(list, "accept-encoding: sdch");
  
  /* 
   * #echo | openssl s_client -showcerts -servername php-dns.appspot.com -connect php-dns.appspot.com:443 2>/dev/null | openssl x509 -inform pem -noout -text
   * #echo | openssl s_client -showcerts -servername dns.google.com -connect dns.google.com:443 2>/dev/null | openssl x509 -inform pem -noout -text
   *
   * #curl --http2 -I 'https://www.fantuz.net/nslookup.php?name=google.it'
   * HTTP/2 200 
   * date: Sat, 03 Mar 2018 16:30:13 GMT
   * content-type: text/plain;charset=UTF-8
   * set-cookie: __cfduid=dd36f3fb91aace1498c03123e646712001520094612; expires=Sun, 03-Mar-19 16:30:12 GMT; path=/; domain=.fantuz.net; HttpOnly
   * x-powered-by: PHP/7.1.12
   * cache-control: public, max-age=14400, s-maxage=14400
   * last-modified: Sat, 03 Mar 2018 16:30:13 GMT
   * etag: 352d3e68703dce365ec4cda53f420f4a
   * accept-ranges: bytes
   * x-powered-by: PleskLin
   * alt-svc: quic=":443"; ma=2592000; v="35,37,38,39"
   * x-turbo-charged-by: LiteSpeed
   * expect-ct: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
   * server: cloudflare
   * cf-ray: 3f5d7c83180326a2-FRA
  */
  
  /* see if H2 goes no-ALPN with no headers set ... */
  curl_easy_setopt(ch, CURLOPT_HEADER, 1L);
  curl_easy_setopt(ch, CURLOPT_HTTPHEADER, list);
  //curl_easy_setopt(ch, CURLINFO_HEADER_OUT, 1L ); /* try to see if it works .. not sure anymore */
  curl_easy_setopt(ch, CURLOPT_NOBODY, 0L); /* get us the resource without a body! */
  curl_easy_setopt(ch, CURLOPT_USERAGENT, "curl/7.59.0-DEV");
  curl_easy_setopt(ch, CURLOPT_HEADERDATA, NULL);
  curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, header_handler);

  /* CURL_LOCK_DATA_SHARE, quite advanced and criptic, useful in H2 */
  /*
  curlsh = curl_share_init();
  curl_easy_setopt(ch, CURLOPT_SHARE, curlsh);
  curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
  */

  /*
  curl_easy_setopt(curl2, CURLOPT_URL, "https://example.com/second");
  curl_easy_setopt(curl2, CURLOPT_COOKIEFILE, "");
  curl_easy_setopt(curl2, CURLOPT_SHARE, shobject);
  */

  /* CURL multi-handler spawner, deactivated for the time being
   * we start some action by calling perform right away
   * curl_multi_perform(multi_handle, &still_running);
  */

  /* Section left for mutlipath or PUSH implementations */
  /*
  // as long as we have transfers going, do work ...
  do {
      struct timeval timeout;
  
      // select() return code
      int rc;
      // curl_multi_fdset() return code
      CURLMcode mc;
  
      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd = -1;
   
      long curl_timeo = -1;
   
      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);
   
      // set a suitable timeout to play around with
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
   
      curl_multi_timeout(multi_handle, &curl_timeo);
      if(curl_timeo >= 0) {
        timeout.tv_sec = curl_timeo / 1000;
        if(timeout.tv_sec > 1)
          timeout.tv_sec = 1;
        else
          timeout.tv_usec = (curl_timeo % 1000) * 1000;
      }
   
      // get file descriptors from the transfers
      mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
   
      if(mc != CURLM_OK) {
        fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
        break;
      }
   
      // On success the value of maxfd is guaranteed to be >= -1. We call
      // select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
      // no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
      // to sleep 100ms, which is the minimum suggested value in the
      // curl_multi_fdset() doc.
   
      if(maxfd == -1) {
          #ifdef _WIN32
              Sleep(100);
              rc = 0;
          #else
      	// Portable sleep for platforms other than Windows
      	struct timeval wait = { 0, 100 * 1000 };
      	// 100ms
      	rc = select(0, NULL, NULL, NULL, &wait);
          #endif
      } else {
        // Note that on some platforms 'timeout' may be modified by select().
        // If you need access to the original value save a copy beforehand.
        rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
      }
   
      switch(rc) {
      case -1:
        // select error
        break;
      case 0:
      default:
        // timeout or readable/writable sockets
        curl_multi_perform(multi_handle, &still_running);
        break;
      }
   
      // A little caution when doing server push is that libcurl itself has
      // created and added one or more easy handles but we need to clean them up
      // when we are done.
   
      do {
        int msgq = 0;;
        m = curl_multi_info_read(multi_handle, &msgq);
        if(m && (m->msg == CURLMSG_DONE)) {
          CURL *e = m->easy_handle;
          transfers--;
          curl_multi_remove_handle(multi_handle, e);
          curl_easy_cleanup(e);
        }
      } while(m);
   
  } while(transfers);
  
  curl_multi_cleanup(multi_handle);
  */

  /* multiple transfers */
  //    for(i = 0; i<num_transfers; i++) {
  //      easy[i] = curl_easy_init();
  //      /* set options */ 
  //      setup(easy[i], i);
  //   
  //      /* add the individual transfer */ 
  //      curl_multi_add_handle(multi_handle, easy[i]);
  //    }

  /* get it! */
  //res = curl_easy_perform(ch);

  /* check for errors */ 
  /*
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  } else {
    printf("%lu bytes retrieved\n", (long)chunk.size);
  }
  */

  /* Now chunk.memory points to memory block chunk.size bytes big and contains the remote file. Do something nice with it! */ 

  /* original ret was from (ch) but testing (hnd) setup now, same story just housekeeping */
  //ret = curl_easy_perform(ch);

  /* slist holds specific headers here, beware of H2 reccomendations mentioned above */
  slist1 = NULL;
  slist1 = curl_slist_append(slist1, "content-type: application/dns-udpwireformat");

  hnd = curl_easy_init();
  curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 1024L); /* 1K test, normally 100K buffer, set accordingly to truncation and other considerations */ 
  curl_easy_setopt(hnd, CURLOPT_URL, script_url);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_FASTOPEN, 1L);
  curl_easy_setopt(hnd, CURLOPT_NOBODY, 0L); /* placeholder for HEAD method */

  /* set whether or not fetching headers, my function doesn't mandatory need such print (headers are always there anyway) */
  curl_easy_setopt(hnd, CURLOPT_HEADER, 0L);
  
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, slist1);
  curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/7.59.0-DEV");
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 2L); /* delegation, RD bit set ? default 50 */

  //curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
  curl_easy_setopt(hnd, CURLOPT_SSL_ENABLE_ALPN, 1L);
  curl_easy_setopt(hnd, CURLOPT_SSL_ENABLE_NPN, 1L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 2L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 2L);
  /* OCSP not always available on cloudflare or cloud providers (OK for Google's GCP, still need to test AWS */
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYSTATUS, 0L);
  curl_easy_setopt(hnd, CURLOPT_FILETIME, 1L);
  curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(hnd, CURLOPT_ENCODING, "br");
  //curl_easy_setopt(hnd, CURLOPT_ENCODING, "deflate");

  if (DEBUGCURL) { curl_easy_setopt(hnd, CURLOPT_VERBOSE,  1); } else { curl_easy_setopt(hnd, CURLOPT_VERBOSE,  0); }
  //curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, write_data); /* send all data to this function */
  //curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, http_response); /* we pass our 'chunk' struct to the callback function */ 
  curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, my_trace);

  if (DEBUG) {
      //snprintf(script_url, URL_SIZE-1, "%s?name=%s", lookup_script, host); // GOOGLE DNS
      fprintf(stderr, " *** %s\n",n);
  }

  /* ret on (hnd) is the H2 cousin of original ret used above for (ch), now temporarely commented out */
  //if (sizeof(host) > 2)
  if (!(host == NULL) || (host == "")) {
    ret = curl_easy_perform(hnd);
    //free(host);
    //host = NULL;
  } else {
    ret = -1;
  }

  /* if(ret != CURLE_OK) { fprintf(stderr, "curl_setopt() failed: %s\n", curl_easy_strerror(ret)); } */
  
  /* Problem in performing the http request */
  if (ret < 0) {
      debug_msg ("Error performing HTTP request (Error %d) - spot on !!!\n");
      printf("Error performing HTTP request (Error %d) - spot on !!!\n",ret);
      curl_easy_cleanup(ch);
      free(script_url);
      curl_slist_free_all(list);
      //curl_share_cleanup(curlsh);
      //curl_slist_free_all(hosting);
      //curl_share_cleanup(curlsh);
      /*this will satisfy the client, with a SERVFAIL at least */
      http_response = "0.0.0.0";
      return http_response;
  }
 
  /* Can't resolve host or packet too big (up to 4096 in UDP and 65595 in TCP) */
  if ((strlen(http_response) > 512) || (strncmp(http_response, "0.0.0.0", 7) == 0)) {
      // insert error answers here, as NXDOMAIN, SERVFAIL etc
      /* In BIND 8 the SOA record (minimum parameter) was used to define the zone default TTL value. */
      /* In BIND 9 the SOA 'minimum' parameter is used as the negative (NXDOMAIN) caching time (defined in RFC 2308). */
      printf(" *** CORE: MALFORMED DNS, possibly a SERVFAIL from origin ? ... \n");
      printf(" *** DNS-over-HTTP server  -> %s\n", script_url);
      printf(" *** Response from libCURL -> %s\n", http_response);
      //curl_slist_free_all(hosting);
      curl_easy_cleanup(ch);
      curl_slist_free_all(list);
      //curl_share_cleanup(curlsh);
      /* this will satisfy the client, with a SERVFAIL at least */
      http_response = "0.0.0.0";
      return http_response;
  }
 
  if (DEBUGCURL) { printf("\n[%s]\n",http_response); }

  curl_easy_cleanup(ch);
  free(script_url);
  //free(proxy_url);
  //free(chunk.memory);
  curl_global_cleanup();
  curl_slist_free_all(list);
  //curl_slist_free_all(hosting);
  //curl_share_cleanup(curlsh);

  /* contains CURL answer */
  return http_response;
}

/* This is our thread function.  It is like main() but for a thread */
void *threadFunc(void *arg) {
  struct readThreadParams *params = (struct readThreadParams*)arg;
  
  //struct dns_request *xdns_req = (struct dns_request *)params->xhostname;
  struct sockaddr_in *yclient = (struct sockaddr_in *)params->yclient;
  //struct sockaddr_in *xclient = (struct sockaddr_in *)params->xclient;
  struct dns_request *dns_req = malloc(sizeof(struct dns_request));
  struct dns_request *xhostname = (struct dns_request *)params->xhostname;
  size_t request_len = params->xrequestlen;
  //char *str;
  //int test = params->digit;
  //char* data = params->input;
  
  int wport = params->xwport, ret;
  
  int proxy_port_t = params->xproxy_port;
  char* proxy_host_t = params->xproxy_host;
  char* proxy_user_t = params->xproxy_user;
  char* proxy_pass_t = params->xproxy_pass;
  
  int xsockfd = params->xsockfd;
  int sockfd = params->sockfd;
  int ttl = params->xttl;
  int proto = params->xproto;
  char* typeq = params->xtypeq;
  char* lookup_script = params->xlookup_script;
  
  char *rip = malloc(256 * sizeof(char)), *ip = NULL, *yhostname = (char *)params->xhostname->hostname;
  
  pthread_key_t key_i;
  pthread_key_create(&key_i, NULL);
  //str=(char*)arg;
  
  /* shall I use trylock or lock ? */
  //if (pthread_mutex_lock(&mutex))
  if (pthread_mutex_trylock(&mutex)) {
    if (EXT_DEBUG) { printf("initial lock OK\n"); }
  } else {
    if (EXT_DEBUG) { printf("initial lock NOT-OK\n"); }
  }
  
  if (DEBUG) {
    //char *p = &xclient->sin_addr.s_addr;
    char *s = inet_ntoa(yclient->sin_addr);
    printf("params->xhostname->hostname		: %s\n",(char *)params->xhostname->hostname);
    //printf("params->xhostname			: %s\n",(char *)params->xhostname);
    printf("proto					: %d\n",params->xproto);
    printf("VARIABLE sin_addr human-readable	: %s\n", s);
    //printf("VARIABLE yhostname			: %s\n", yhostname);
    //printf("xdns_req->hostname			: %s\n",(char *)xdns_req->hostname);
    //printf("VARIABLE sin_addr			: %d\n", (uint32_t)(yclient->sin_addr).s_addr);
  }
  
  //if (!(yhostname == NULL))
  if (!(params->xhostname->hostname == NULL)) {
    rip = lookup_host(yhostname, proxy_host_t, proxy_port_t, proxy_user_t, proxy_pass_t, lookup_script, typeq, wport);
    yhostname == NULL;
    params->xhostname->hostname == NULL;
  } else {
    rip == "0.0.0.0";
    yhostname == NULL;
    exit(EXIT_SUCCESS);
  }

  /* PTHREAD SET SPECIFIC GLOBAL VARIABLE ... */
  pthread_setspecific(glob_var_key_ip, rip);
  pthread_getspecific(glob_var_key_ip);
  
  //printf("VARIABLE-RET-HTTP-GLOBAL: %x\n", glob_var_key_ip);
  //printf("VARIABLE-HTTP: %x\n", pthread_getspecific(glob_var_key_ip));
  //printf("build: %s", inet_ntop(AF_INET, &ip_header->saddr, ipbuf, sizeof(ipbuf)));
  
  if (EXT_DEBUG) {
    printf("\nTHREAD CURL-RET-CODE			: %d\n", ret);
    printf("\nTHREAD CURL-RESULT			: [%s]\n", rip);
    printf("THREAD-MODE-ANSWER			: %d\n", DNS_MODE_ANSWER);
    printf("THREAD-proxy-host			: %s\n", params->xproxy_host);
    printf("THREAD-proxy-port			: %d\n", params->xproxy_port);
    printf("THREAD-proxy-host			: %s\n", proxy_host_t);
    printf("THREAD-proxy-port			: %d\n", proxy_port_t);
  }
  
  if ((rip != NULL) && (strncmp(rip, "0.0.0.0", 7) != 0)) {
    if (DEBUG) {
	printf("THREAD-V-size				: %u\n", (uint32_t)request_len);
	printf("THREAD-typeq				: %s\n", typeq);
	printf("THREAD-dns_req->qtype			: %d\n", dns_req->qtype);
	printf("THREAD-V-socket-Xsockfd			: %u\n", xsockfd);
	printf("THREAD-V-socket- sockfd			: %u\n", sockfd);
	printf("THREAD-V-xclient->sin_addr.s_addr	: %u\n", (uint32_t)(yclient->sin_addr).s_addr);
	printf("THREAD-V-xclient->sin_port		: %u\n", (uint32_t)(yclient->sin_port));
	printf("THREAD-V-xclient->sin_family		: %u\n", (uint32_t)(yclient->sin_family));

	/*
	printf("THREAD-V-xhostname				: %s\n", yhostname);
	printf("THREAD-V-dns-req->hostname			: %s\n", dns_req->hostname);
	printf("THREAD-V-xdns_req->hostname-to-char		: %s\n", (char *)(xdns_req->hostname));
	printf("THREAD-V-xclient->sin_addr.s_addr		: %s\n",(char *)(xclient->sin_family));
	*/
    }
    build_dns_response(sockfd, yclient, xhostname, rip, DNS_MODE_ANSWER, request_len, ttl, proto);
      
  } else if ( strstr(dns_req->hostname, "hamachi.cc") != NULL ) {
    printf("BALCKLIST: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, rip, (uint32_t)request_len);
    //printf("BLACKLIST: xsockfd %d - hostname %s \r\n", xsockfd, xdns_req->hostname);
    printf("BLACKLIST: xsockfd %d - hostname %s \r\n", xsockfd, yhostname);
    build_dns_response(sockfd, yclient, xhostname, rip, DNS_MODE_ANSWER, request_len, ttl,proto);
  
  } else if ((rip == "0.0.0.0") || (strncmp(rip, "0.0.0.0", 7) == 0)) {
    printf(" *** ERROR: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, rip, (uint32_t)request_len);
    printf(" *** ERROR: xsockfd %d - hostname %s \r\n", xsockfd, yhostname);
    printf(" *** Generic/unknown DNS-over-HTTP resolution problem. Contact Massimiliano Fantuzzi.\n");
    //close(sockfd);
    build_dns_response(sockfd, yclient, xhostname, rip, DNS_MODE_ERROR, request_len, ttl, proto);
    //exit(EXIT_SUCCESS);
  }
  
  //char *s = inet_ntoa(xclient->sin_addr);
  pthread_setspecific(glob_var_key_ip, NULL);
  
  if (pthread_mutex_unlock(&mutex)) {
    if (EXT_DEBUG) { printf("unlock OK for thread/process ID: %d\n", getpid()); }
  } else {
    if (EXT_DEBUG) { printf("unlock NOT-OK\n"); }
  } 
  
  if (pthread_mutex_destroy(&mutex)) {
    if (EXT_DEBUG) { printf("destroy OK\n"); }
  } else {
    if (EXT_DEBUG) { printf("destroy NOT-OK\n"); }
  }
  
  /* Again, quit the thread */
  //pthread_exit(NULL);
  exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  int sockfd, fd, port = DEFAULT_LOCAL_PORT, wport = DEFAULT_WEB_PORT, proxy_port = 0, c;
  int r = 0;
  int ttl_in;
  char *stack;            /* Start of stack buffer */
  char *stackTop;         /* End of stack buffer */
  pid_t pid;
  struct utsname uts;
  struct sockaddr_in serv_addr;
  struct sockaddr_in serv_addr_tcp;
  struct hostent *local_address;
  //struct hostent *proxy_address;
  //char *bind_proxy = NULL;
  char *bind_address_tcp = NULL, *bind_address = NULL, *proxy_host = NULL, *proxy_user = NULL,
       *proxy_pass = NULL, *typeq = NULL, *lookup_script = NULL,
       *httpsssl = NULL;

  opterr = 0;
     
  /* deactivating mutexes, leaving all placeholders */
  /*
  //sem_t mutex;
  sem_t sem;
  sem_t *mutex;
  */

  int s, tnum, opt, num_threads;
  struct thread_info *tinfo;
  pthread_attr_t attr;

  int stack_size;
  void *res;
  int thr = 0;
  int *ptr[2];

  /* The "-s" option specifies a stack size for our threads, I guess unlimited is not a good idea */
  stack_size = -1;

  /*
  const char    * short_opt = "hf:";
  struct option   long_opt[] = {
     {"help",          no_argument,       NULL, 'h'},
     {"file",          required_argument, NULL, 'f'},
     {NULL,            0,                 NULL, 0  }
  };
  */
  
  /* Command line args */
  // while ((c = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1)
  
  while ((c = getopt (argc, argv, "T:s:p:l:r:H:t:w:u:k:hvCXn")) != -1)
  switch (c)
   {
      case 't':
          stack_size = strtoul(optarg, NULL, 0);
          fprintf(stdout," *** Stack size %d\n",stack_size);
      break;

      case 'p':
          port = atoi(optarg);
          if (port <= 0) {
              fprintf(stdout," *** Invalid local port\n");
              exit(EXIT_FAILURE);
          }
      break;

      case 'w':
          wport = atoi(optarg);
          if (wport <= 0) {
              fprintf(stdout," *** Invalid webserver port\n");
              printf(" *** Invalid webserver port: %d\n", wport);
              exit(EXIT_FAILURE);
          }
      break;

      case 'r':
          proxy_port = atoi(optarg);
          if ((proxy_port <= 0) || (proxy_port >= 65536)) {
              fprintf(stdout," *** Invalid proxy port\n");
              exit(EXIT_FAILURE);
          }
      break;
              
      case 'C':
          DEBUGCURL = 1;
          fprintf(stderr," *** verbose CURL ON\n");
      break;

      case 'X':
          EXT_DEBUG = 1;
          fprintf(stderr," *** EXTENDED DEBUG ON\n");
      break;

      case 'v':
          DEBUG = 1;
          fprintf(stderr," *** DEBUG ON\n");
      break;

      case 'T':
          ttl_in = atoi(optarg);
          fprintf(stderr," *** TTL SET TO %d, 4 bytes, 0-2147483647 seconds (RFC 2181)\n",ttl_in);
      break;

      case 'n':
          DNSDUMP = 1;
          fprintf(stderr," *** DNSDUMP HEX-MODE ON\n");
      break;
      
      case 'l':
          bind_address = (char *)optarg;
      break;

      case 'H':
          proxy_host = (char *)optarg;
      break;

      case 'u':
          proxy_user = (char *)optarg;
      break;

      case 'k':
          proxy_pass = (char *)optarg;
      break;

      case 's':
          lookup_script = (char *)optarg;
      break;

      case 'h':
          usage();
      break;

      case '?':
          if (optopt == 'p')
              fprintf(stderr," *** Invalid local port\n");
          else 
          if (optopt == 'w')
              fprintf(stderr," *** Invalid webserver port\n");
          else 
          if (optopt == 'r')
              fprintf(stderr," *** Invalid proxy port\n");
          else 
          if (optopt == 's')
              fprintf(stderr," *** Invalid lookup script URL\n");
          else 
          if  (optopt == 't')
              fprintf(stderr," *** Invalid stack size\n");
          else
          if (isprint(optopt))
              fprintf(stderr," *** Invalid option -- '%c'\n", optopt);
          usage();
      break;
      
      default:
      //fprintf(stderr, "Usage: %s [-s stack-size] arg...\n", argv[0]);
      exit(EXIT_FAILURE);
      abort();
  }

  if (proxy_host != NULL) {
      fprintf(stderr, "Yay !! HTTP caching proxy configured, continuing with support of HTTP cache\n");
      fprintf(stderr, "Using proxy-host: %s\n",proxy_host);
      //proxy_host = proxy_address;
      //fprintf(stderr, "Bind proxy string: %s\n",proxy_address);
  } else {
      fprintf(stderr, "No HTTP caching proxy configured, continuing without HTTP cache\n");
  }	

  if (bind_address == NULL) { bind_address = "127.0.0.1"; bind_address_tcp = "127.0.0.1"; }
  if (lookup_script == NULL) { usage(); }

  /* Prevent child process from becoming zombie process */
  signal(SIGCLD, SIG_IGN);

  /* libCurl init */
  curl_global_init(CURL_GLOBAL_ALL);

  /* TCP REUSE KERNEL SUPPORT TEST */
  /*
  #ifdef SO_REUSEPORT
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int reuseport = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuseport, sizeof(reuseport)) < 0) {
      if (errno == EINVAL || errno == ENOPROTOOPT) {
        printf("SO_REUSEPORT is not supported by your kernel\n");
      } else {
        printf("unknown error\n");
      }
    } else {
      printf("SO_REUSEPORT is supported\n");
    }
    close(sock);
  #else
    printf("SO_REUSEPORT is not supported by your include files\n");
  #endif
  
  #ifdef SO_REUSEADDR
    int sock2 = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    if (setsockopt(sock2, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
      if (errno == EINVAL || errno == ENOPROTOOPT) {
        printf("SO_REUSEADDR is not supported by your kernel\n");
      } else {
        printf("unknown error\n");
      }
    } else {
      printf("SO_REUSEADDR is supported\n");
    }
    close(sock2);
  #else
    printf("SO_REUSEADDR is not supported by your include files\n");
  #endif
  */

  /*
  memset(&serv_addr, 0, sizeof(serv_addr)); 
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(10000); //arbitrary port number...
  serv_addr.sin_addr.s_addr = inet_addr(host_addr);
  // connect socket to the above address
  if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("Error : Connect Failed. %s \n", strerror(errno));
    return 1;
  }  
  */

  /* socket() */
  sockfd = socket(AF_INET, SOCK_DGRAM, 17);
  int reusea = 1, reusep = 1;
  if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEPORT, (const char*)&reusep,sizeof(reusep))==-1) { printf("%s",strerror(errno)); }
  if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR, (const char*)&reusea,sizeof(reusea))==-1) { printf("%s",strerror(errno)); }
  int socketid = 0;
  if (sockfd < 0) error("Error opening socket");
  if ((socketid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) error("socket(2) failed");

  /* local address listener guessing UDP */
  bzero((char *) &serv_addr, sizeof(serv_addr));
  local_address = gethostbyname(bind_address);
  if (local_address == NULL) error("Error resolving local host");
  
  serv_addr.sin_family = AF_INET;
  memcpy (&serv_addr.sin_addr.s_addr, local_address->h_addr,sizeof (struct in_addr));
  serv_addr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("Error opening socket (bind)");

  fd = socket(AF_INET, SOCK_STREAM, 6);
  if (fd<0) { printf(" *** %s",strerror(errno)); }

  int reuseaddr = 1, reuseporttwo = 1;
  if (setsockopt(fd,SOL_SOCKET,SO_REUSEPORT, (const char*)&reuseporttwo,sizeof(reuseporttwo))==-1) { printf("%s",strerror(errno)); }
  if (setsockopt(fd,SOL_SOCKET,SO_REUSEADDR, (const char*)&reuseaddr,sizeof(reuseaddr))==-1) { printf("%s",strerror(errno)); }

  int socketidtcp = 0;
  if (fd < 0) error("Error opening socket");
  if ((socketidtcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) error("socket(2) failed");
  //fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  /* local address listener guessing TCP */
  bzero((char *) &serv_addr_tcp, sizeof(serv_addr_tcp));
  memset(&serv_addr_tcp, 0, sizeof(serv_addr_tcp)); 
  local_address = gethostbyname(bind_address_tcp);
  if (local_address == NULL) error("Error resolving local host");
  serv_addr_tcp.sin_family = AF_INET;
  serv_addr_tcp.sin_port = htons( PORT );
  serv_addr_tcp.sin_addr.s_addr = inet_addr(bind_address_tcp);
  //memcpy (&serv_addr.sin_addr.s_addr, local_address->h_addr,sizeof (struct in_addr));

  /* if (bind(server_fd,res->ai_addr,res->ai_addrlen)==-1) */
  //if (bind(fd,(struct sockaddr *) &serv_addr->ai_addr, sizeof(serv_addr))==-1) { printf("%s",strerror(errno)); }
  
  //int xxx = sizeof(serv_addr);
  //if (bind(fd,(struct sockaddr *) &serv_addr, sizeof(serv_addr)==-1)) { printf("%s",strerror(errno)); }
  //if (bind(fd,(struct sockaddr *) &serv_addr, &xxx)==-1) { printf("%s",strerror(errno)); }
  bind(fd, (struct sockaddr *) &serv_addr_tcp, sizeof(serv_addr_tcp));
  if ((listen(fd, SOMAXCONN)==-1)) { printf("%s",strerror(errno)); }
  int cnt = 0;
  int flag;

  int reusead = 0, reusepo = 0;
  if (setsockopt(fd,SOL_SOCKET,SO_REUSEPORT, (const char*)&reusepo,sizeof(reusepo))==-1) { printf("%s",strerror(errno)); }
  if (setsockopt(fd,SOL_SOCKET,SO_REUSEADDR, (const char*)&reusead,sizeof(reusead))==-1) { printf("%s",strerror(errno)); }

  /* selfconnect test */
  //if (connect(fd, (struct sockaddr *) &serv_addr_tcp, sizeof(serv_addr_tcp)) < 0) error("caca");;
  
  /* semaphores section, if ever needed */
  /*
  if(sem_init(*sem_t,1,1) < 0) { perror("semaphore initilization"); exit(2); }
  if(sem_init(&mutex,1,1) < 0) { perror("semaphore initilization"); exit(2); }
  if ((mutex = sem_open("/tmp/semaphore", O_CREAT, 0644, 1)) == SEM_FAILED ) { perror("sem_open"); exit(EXIT_FAILURE); }
  */

  if(pthread_mutex_init(&mutex, &MAttr)) { printf("Unable to initialize a mutex while talking threads\n"); return -1; }

  //fcntl(fd, F_SETFL, O_NONBLOCK);

  while (1) {

    int nnn = 0;
    uint i = 0;
    int s, tnum, opt, stack_size, rc, t, status;
    unsigned int request_len, client_len;
    unsigned int request_len_tcp, client_len_tcp;
    unsigned int new_socket_len;
    
    char *ip = NULL;
    char request[UDP_DATAGRAM_SIZE + 1];
    char request_tcp[TCP_DATAGRAM_SIZE + 1];
    
    struct dns_request *dns_req;
    struct dns_request *dns_req_tcp;
    struct sockaddr client;
    struct sockaddr client_tcp;

    pthread_mutexattr_init(&MAttr);
    //pthread_mutexattr_settype(&MAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutexattr_settype(&MAttr, PTHREAD_MUTEX_RECURSIVE);
    
    struct thread_info *tinfo;
    
    /* Initialize and set thread detached attribute */
    //pthread_id_np_t   tid;
    //tid = pthread_getthreadid_np();
    wait(NULL);
    
    pthread_t *pth = malloc( NUMT * sizeof(pthread_t) ); // this is our thread identifier
    //pthread_t *tid = malloc( NUMT * sizeof(pthread_t) );
    pthread_t thread[NUM_THREADS];
    //static pthread_t tidd;
    
    //struct thread_data data_array[NUM_THREADS];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    /* wrong ... DO NOT USE */
    //sem_wait(&mutex);
    pthread_mutex_trylock(&mutex);
    //pthread_mutex_destroy(&mutex);

    /* client */
    client_len = sizeof(client);
    client_len_tcp = sizeof(client_tcp);

    /* UDP listener */
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    //fcntl(sockfd, F_SETFL, FNDELAY);
    request_len = recvfrom(sockfd,request,UDP_DATAGRAM_SIZE,0,(struct sockaddr *)&client,&client_len);

    /* TCP listener */
    fcntl(fd, F_SETFL, O_NONBLOCK);
    fcntl(fd, F_SETFL, FNDELAY);
    //int new_socket = accept(int fd, struct sockaddr *serv_addr_tcp, socklen_t *addrlen);
    //int newsockfd = accept(fd, (struct sockaddr *) &client_tcp, sizeof(client_tcp));
    
    int newsockfd;
    //int sndbuf = 512;
    //int rcvbuf = 512;
    //int yes = 1;
    //setsockopt(newsockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(sndbuf));
    //setsockopt(newsockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(rcvbuf));
    //setsockopt(newsockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    
    if (cnt == 0) {
      newsockfd = fd;
      request_len_tcp = recvfrom(fd,request_tcp,TCP_DATAGRAM_SIZE,MSG_DONTWAIT,(struct sockaddr *)&client,&client_len);
      //request_len_tcp = recvfrom(fd,request_tcp,TCP_DATAGRAM_SIZE,0,(struct sockaddr *)&client,&client_len);
      cnt++;
    } else {
      newsockfd = accept(fd, (struct sockaddr *) &client_tcp, &client_len_tcp);
      //newsockfd = accept(fd, (struct sockaddr *) &client, &client_len);
      fcntl(newsockfd, F_SETFL, FNDELAY);
      fcntl(newsockfd, F_SETFL, O_NONBLOCK);
      //request_len_tcp = recvfrom(newsockfd,request_tcp,TCP_DATAGRAM_SIZE,MSG_WAITALL,(struct sockaddr *)&client,&client_len);
      request_len_tcp = recvfrom(newsockfd,request_tcp,TCP_DATAGRAM_SIZE,MSG_WAITALL,(struct sockaddr *)&client_tcp,&client_len_tcp);
      //request_len_tcp = recvfrom(newsockfd,request_tcp,TCP_DATAGRAM_SIZE,0,(struct sockaddr *)&client_tcp,&client_len_tcp);
    }

    //fcntl(newsockfd, F_SETFL, O_NONBLOCK);
    //request_len_tcp = recvfrom(newsockfd,request,TCP_DATAGRAM_SIZE,MSG_DONTWAIT,(struct sockaddr *)&client_tcp,sizeof(client_tcp));
    //if ((accept(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0) { printf("\nERROR IN INITIAL ACCEPT\n"); close(fd); } else { printf("\nNO ERROR IN INITIAL ACCEPT\n"); }
    //if ((accept(fd, (struct sockaddr *) &client, sizeof(&client))) < 0) { printf("\nERROR IN ACCEPT\n"); //close(fd); } else { printf("\nNO ERROR IN ACCEPT\n"); }
    
    //wait(NULL);
    
    /* Child */
    /* Allocate stack for child */
    stack = malloc(STACK_SIZE);
    if (stack == NULL) errExit("malloc");
    
    /* Assume stack grows downward */
    stackTop = stack + STACK_SIZE;
    
    /* Create child that has its own UTS namespace; child commences execution in childFunc() */
    
    /* Clone function */
    /*
    pid = clone(parse_dns_request, stackTop, CLONE_NEWUTS | SIGCHLD, argv[1]);
    //pid = clone(parse_dns_request, stackTop, CLONE_VM | SIGCHLD, argv[1]);
    //if (pid == -1)
    //    errExit("clone");
    //printf("clone() returned %ld\n", (long) pid);
    sleep(1);           
    */
    
    //wait(NULL);
    
    /* Give child time to change its hostname */
    /* CLONE process/thread */
    // pid = clone(fn, stack_aligned, CLONE_VM | SIGCHLD, arg);
    // pid = clone(childFunc, stackTop, CLONE_NEWUTS | SIGCHLD, argv[1]);
    // posix_spawn()
    
    /* PID/clone() PLACEHOLDER LEFT FOR HOUSEKEEPING: processes */
    // pid = clone(parse_dns_request, stack_aligned, CLONE_VM | SIGCHLD, request request_len);
    //if (pid == 0) 
    //if (clone(parse_dns_request, stack_aligned, CLONE_VM | SIGCHLD, request, request_len)) 
    
    /* still monolithic, takes millions of queries but thread/processes can be parallelised easily in C or in CURL */
    if (vfork() == 0) {
    
      /* LEFT FOR HOUSEKEEPING, SEMAPHORE LOGIC */
      //sem_wait(&mutex);
    
      /*
       * The core corresponding DNS lookup is made ONCE (via CURL/HTTP 1 or 2 against nslookup.php, nslookup-doh.php) 
       * Retry methods are specified outside of the working-group draft DOH.
       * SUCH ANSWER MIGHT BE CACHED IN THE NETWORK (polipo, memcache, CDN, CloudFlare, Varnish, GCP, ...)
       * DNSP IMPLEMENTS DOMAIN BLACKLISTING, AUTHENTICATION, SSL, THREADS... simple and effective !
      */
    
      int ret, proto, xsockfd;
      int ttl; // strictly 4 bytes, 0-2147483647 (RFC 2181)
      //int test = 42; // the answer, used in alpha development
      int xwport = wport; // web port, deprecated
      //char* str = "maxnumberone"; // another pun
      char* xlookup_script = lookup_script;
      char* xtypeq = typeq;
      struct dns_request *xhostname;
      struct sockaddr_in *xclient;
      struct sockaddr_in *yclient;
      struct readThreadParams *readParams = malloc(sizeof(*readParams));
      // int xproxy_port = proxy_port; char* xproxy_user = proxy_user; char* xproxy_pass = proxy_pass; char* xproxy_host = proxy_host;

      //if (request_len_tcp == -1) { dns_req_tcp = parse_dns_request(request_tcp, request_len_tcp + 2, 1); flag = 1; }
      //if (dns_req == NULL) { flag = 0; } //if (dns_req_tcp == NULL) { flag = 1; } 

      //if (flag == 1) {
      if (request_len == -1) {
	flag = 1;
	cnt++;
      	dns_req_tcp = parse_dns_request(request_tcp, request_len_tcp, 1);
        if (EXT_DEBUG) { fprintf(stderr, "QUANTITY TCP: %x - %d\n", request_tcp, request_len_tcp); }
	if (cnt == 0) { readParams->sockfd = fd; } else { readParams->sockfd = newsockfd; }
        dns_req_tcp->qtype == 0x01;
        readParams->xproto = 1;
        readParams->xclient = (struct sockaddr_in *)&client;
        readParams->yclient = (struct sockaddr_in *)&client;
        readParams->xrequestlen = request_len_tcp;
        readParams->xhostname = (struct dns_request *)dns_req_tcp;
        //readParams->xhostname = dns_req_tcp->hostname;
        //readParams->xhostname = (struct dns_request *)dns_req;
        //readParams->xdns_req = (struct dns_request *)&dns_req_tcp;
      //} else if (request_len_tcp == -1) {
      } else {
	flag = 0;
        dns_req = parse_dns_request(request, request_len, 0);
        if (EXT_DEBUG) { fprintf(stderr, "QUANTITY UDP: %x - %d\n", request, request_len); }
        readParams->sockfd = sockfd;
        readParams->xproto = 0;
        readParams->xclient = (struct sockaddr_in *)&client;
        readParams->yclient = (struct sockaddr_in *)&client;
        readParams->xrequestlen = request_len;
        readParams->xhostname = (struct dns_request *)dns_req;
        //readParams->xhostname = dns_req->hostname;
        //readParams->xdns_req = (struct dns_request *)&dns_req;
      }
      // else { flag = NULL; } 
      
      /*
      if ((dns_req == NULL) || (dns_req_tcp == NULL)) {
        //printf("BL: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, ip, request_len);
        printf("\nINFO-FAIL: transaction: %x - name %s - size %d \r\n", dns_req->transaction_id, dns_req->hostname, request_len);
        printf("\nINFO-FAIL: transaction: %x - name %s - size %d \r\n", dns_req_tcp->transaction_id, dns_req_tcp->hostname, request_len_tcp);
        exit(EXIT_FAILURE);
      }
      */

      /* QUERY DETECTION, for example see https://en.wikipedia.org/wiki/List_of_DNS_record_types */
      // AAAA is 0x1c, dec 28.  //6 SOA
    
      //if (dns_req_tcp->proto == 1) { dns_req->qtype == 0x01; }
      //if ((request_len == -1) && (request_len_tcp == -1)) { continue; }
      
      if (flag == 1) {
        if (dns_req_tcp->qtype == 0x02) {
          typeq = "NS";
        } else if (dns_req_tcp->qtype == 0x0c) {
          typeq = "PTR";
        } else if (dns_req_tcp->qtype == 0x05) {
          typeq = "CNAME";
        } else if (dns_req_tcp->qtype == 0x01) {
          typeq = "A";
          printf("TCP gotcha qtype: %x // %d\r\n",dns_req_tcp->qtype,dns_req_tcp->qtype); //PTR ?
          printf("TCP gotcha tid  : %x // %d\r\n",dns_req_tcp->transaction_id,dns_req_tcp->transaction_id); //PTR ?
        } else if (dns_req_tcp->qtype == 0x0f) {
          typeq = "MX";
        } else { //{ dns_req->qtype == 0xff;} 
          printf("TCP gotcha qtype: %x // %d\r\n",dns_req->qtype,dns_req->qtype); //PTR ?
          printf("TCP gotcha tid  : %x // %d\r\n",dns_req->transaction_id,dns_req->transaction_id); //PTR ?
        }
      } else if (flag == 0) {
        if (dns_req->qtype == 0x02) {
          typeq = "NS";
        } else if (dns_req->qtype == 0x0c) {
          typeq = "PTR";
        } else if (dns_req->qtype == 0x05) {
          typeq = "CNAME";
        } else if (dns_req->qtype == 0x01) {
          typeq = "A";
          printf("UDP gotcha qtype: %x // %d\r\n",dns_req->qtype,dns_req->qtype); //PTR ?
          printf("UDP gotcha tid  : %x // %d\r\n",dns_req->transaction_id,dns_req->transaction_id); //PTR ?
        } else if (dns_req->qtype == 0x0f) {
          typeq = "MX";
        } else { //{ dns_req->qtype == 0xff;} 
          printf("UDP gotcha qtype: %x // %d\r\n",dns_req->qtype,dns_req->qtype); //PTR ?
          printf("UDP gotcha tid  : %x // %d\r\n",dns_req->transaction_id,dns_req->transaction_id); //PTR ?
        }
      } else if ( flag == NULL) {
        continue;
      }

      /* PLACEHOLDER FOR HTTP options, DoH full-spec, CLOUD deploys */
      //	  readParams->max_req_client = 10;
      //	  readParams->random = 0;
      //	  readParams->ssl = 0;
      //	  readParams->uselogin = 1;
    
      if (ttl_in == NULL) {
        printf("TTL not set, forcing 84600 for test");
	ttl = 86400;
      } else {
        ttl = ttl_in;
      }
    
      readParams->xlookup_script = lookup_script;
      readParams->xtypeq = typeq;
      readParams->xwport = wport;
      readParams->xttl = ttl;

      readParams->xproxy_user = proxy_user;
      readParams->xproxy_pass = proxy_pass;
      readParams->xproxy_host = proxy_host;
      readParams->xproxy_port = proxy_port;

      /*
      readParams->xhostname = (struct dns_request *)dns_req;
      readParams->xdns_req = (struct dns_request *)&dns_req;
      readParams->xsockfd = xsockfd;
      readParams->sockfd = sockfd;
      readParams->xproto = proto;
      readParams->xrequestlen = request_len;
      readParams->xclient = (struct sockaddr_in *)&client;
      readParams->yclient = (struct sockaddr_in *)&client;
      */
      
      //if ((!(readParams->xhostname == NULL) && (flag == 1))) {
      //if ((!(readParams->xhostname->hostname == NULL))) {
      
      //if ((!(readParams->xhostname == NULL)) || (!(readParams->xhostname->hostname == NULL))) {
      //if ((readParams->xhostname == NULL)) {
      //if ((readParams->xhostname->hostname == NULL)) {
      if ((dns_req->hostname == NULL) && (dns_req_tcp->hostname == NULL)) {
	printf("met no-host condition ! fail flag: %d, fail count: %d\n",flag,cnt);
	//readParams->xhostname = "www.example.com";
	//printf("new hostname: %s\n", readParams->xhostname);
	flag == NULL;
	continue;
      }

      printf("dns_req_tcp->hostname, dns_req->hostname		\n: %s // %s\n", dns_req_tcp->hostname, dns_req->hostname);
      printf("readParams->xhostname->hostname, readParams->xhostname	\n: %s // %s\n", readParams->xhostname->hostname, readParams->xhostname);

      //readParams->input = str;
      //readParams->digit = test;
      //free(out_array);
    
      /* LEFT FOR HOUSEKEEPING: thread retuns if needed */
      tinfo = calloc(NUMT, sizeof(struct thread_info));
      if (tinfo == NULL) handle_error("calloc");

      /* AS DISCUSSED, I am now sticking to monolithic/vfork */
      /* Waiting stable specs for DNS-over-HTTP https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-04 */
    
      /* Here just checking if any issue in creating a new THREAD ? NO issuses BTW errore means error in italian :) */
      //errore = pthread_create(&tid[i], NULL, threadFunc, &data_array[i]);
      //if (i=sizeof(pth)) { i = 0 ;}
    
      if (pthread_mutex_trylock(&mutex)) {
      //ret = pthread_create(&pth[i],NULL,threadFunc,readParams);
        if (DEBUG) { printf("PTHREAD lock OK ...\n"); }
      } else {
        if (DEBUG) { printf("PTHREAD lock NOT OK ...\n"); }
      }
    
      /* Spin the well-instructed thread ! */

      printf("flag: %d, count: %d\n",flag,cnt);
      threadFunc(readParams);
      ret = pthread_create(&pth[i],&attr,threadFunc,readParams);
          
      /* ONLY IF USING SEMAPHORES .... NOT WITH MUTEX */
      //sem_wait(&mutex);
      //sem_post(&mutex);
    
      /* USEFUL for future with QUIC support (multipath/UDP) */
      for(r=0; r < NUMT*NUM_THREADS; r++) {
      	if(0 != ret) {
      	fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, ret);
              //char *vvv = pthread_getspecific(glob_var_key_ip);
              //printf("GLOBAL-FAIL-IP: %s\n", vvv);
        } else {
              //char *vvv = pthread_getspecific(glob_var_key_ip);
              //printf("GLOBAL-SUCC-IP: %s\n", vvv);
        }
    
        /* joiing is the trick */
        //pthread_join(pth[i],NULL);
        //pthread_join(pth[r],NULL);
        //tidd = pthread_self();
        //fprintf(stderr, "self r - %d \n",pthread_self(pth[i]));
    
        if (DEBUG) {
          //fprintf(stderr, "pth i - %d \n",(uint16_t)pth[i]);
          //fprintf(stderr, "pth r - %d \n",(uint16_t)pth[r]);
          //printf("OUTSIDE-THREAD-resolved-address: %s\n",ip);
          //printf("OUTSIDE-THREAD-resolved-address: %d\n",ret);
          //printf("OUTSIDE-THREAD-resolved-address: %d\n",glob_var_key_ip);
          //printf("OUTSIDE-THREAD-log: pid [%u] - hostname %s - size %d ip %s\r\n", ret, dns_req->hostname, request_len, ip);
          printf("OUTSIDE-THREAD-log: size %d\n",request_len);
          fprintf(stderr, " *** Finished joining thread i-> %d, nnn-> %d, r-> %d \n",i,nnn,r);
        }

        printf("OUTSIDE-THREAD-log: size %d\n",request_len);
        fprintf(stderr, " *** Finished joining thread i-> %d, nnn-> %d, r-> %d \n",i,nnn,r);
        i++;
        nnn++;
      }
    
      if (nnn > NUMT*NUM_THREADS * 2) { wait(NULL); }

      printf("IF: Thread/process ID : %d\n", getpid());
      pthread_mutex_destroy(&mutex);
      //if (i != 0) { i=0;}
      pthread_join(pth[i],NULL);
      /* trying to re-enable this logic, continue shouldnt be before pthread_setspecific() */
      /* testing destroy after join, and before setspecific, seems right */
      pthread_attr_destroy(&attr);
      pthread_setspecific(glob_var_key_ip, NULL);
      continue;
    
    } else {
    
      nnn++;
      // RECOVER FROM THREAD BOMB SITUATION
      //printf(" **** BIG FAULT with thread/process ID : %d\n", getpid());
      //if (nnn > 32) {wait(NULL);}
      //exit(EXIT_SUCCESS);
      /* sometimes you just need to take a break, or continue .. */
      //break;
      continue;
    
      /* Span N number of threads */
      /*
      for(nnn=0; nnn< NUMT; nnn++) {
          //struct sockaddr_in *xclient = (struct sockaddr_in *)params->xclient;
      	//pthread_join(tid[i],(void**)&(ptr[i])); //, (void**)&(ptr[i]));
      	//printf("\n return value from last thread is [%d]\n", *ptr[i]);
      	//pthread_join(pth[i],NULL);
      }
      */
    
      /* LOCKS AND MUTEXES */
      /*
      pthread_mutex_lock(&mutex);
      if (pthread_mutex_unlock(&mutex)) {
          //printf("FAILED, unlock OK.. but no RET\n");
      continue;
      } else {
          printf("FAILED, unlock NOT OK.. and no RET\n");
      } 
      */
    
      /* Semaphores section */
      //sem_destroy(&mutex);
    
      /* JOIN THREADS, rejoin and terminate threaded section */
      /*
      if(pthread_join(pth[i], NULL)) {
      	//fprintf(stderr, "Finished serving client %s on socket %u \n",(struct sockaddr_in *)&client->sin_addr.s_addr,sockfd);
      }
      */
    
      /* LOCKS AND MUTEXES */
      /*
      //pthread_mutex_destroy(&mutex);
      // DO NOT USE
      //sem_post(&mutex); // sem_post is fun and dangerous
      */
      
      /* THREAD JOIN ENDING, RELEASE */
      /*
      //pthread_join(pth[i],NULL);
      //pthread_exit(NULL);
      */
    
      // NONSENSE CAUSE WE WOULD NOT BE IN THE THREAD ANYMORE ... LEFT FOR HOUSEKEEPING
      //if (DEBUG) {fprintf(stderr, "Finished joining thread i-> %d, nnn-> %d \n",i,nnn);}
      //exit(EXIT_FAILURE); // did we ?
    }
  }
}

