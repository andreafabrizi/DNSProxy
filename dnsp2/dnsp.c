/*
 * DNS proxy 1.01
 *  
 * Copyright (C) 2014-2015 Massimiliano Fantuzzi <superfantuz@gmail.com>
 * Copyright (C) 2009-2013 Andrea Fabrizi <andrea.fabrizi@gmail.com>
 *  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Especially, no
 * "INTERNET PRIVACY" is guaranteed, except within lab testing. See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <sys/timeb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <signal.h>
//#include <semaphore.h>
//#include <omp.h>


#ifndef SIGCLD
#   define SIGCLD SIGCHLD
#endif

#define DELAY		    0
#define MAXCONN             1
#define UDP_DATAGRAM_SIZE   256
#define DNSREWRITE          256
#define HTTP_RESPONSE_SIZE  256
#define URL_SIZE            256
#define VERSION             "1.01"
#define DNS_MODE_ANSWER     1
#define DNS_MODE_ERROR      2
#define DEFAULT_LOCAL_PORT  53
#define DEFAULT_WEB_PORT    80
#define NUMT	            1
#define NUM_THREADS         1
#define NUM_HANDLER_THREADS 1

//#define TYPEQ		    2
//#define DEBUG		    0

#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while (0)

//pthread_key_t glob_var_key_ip;
//pthread_key_t glob_var_key_client;

/*
//static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
//pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
pthread_mutexattr_t MAttr;
*/

/*
#ifdef TLS
__thread int i;
#else
 pthread_key_t key_i;
#endif
 pthread_t *tid;
*/

struct readThreadParams {
    size_t xrequestlen;
    char* xproxy_user;
    char* xproxy_pass;
    char* xproxy_host;
    int xproxy_port;
    char* xlookup_script;
    char* xtypeq;
    int xwport;
    int sockfd;
    int xsockfd;
    //char* xhostname;
    //int digit;
    //char* input;
    struct dns_request *xhostname;
    struct sockaddr_in *xclient;
    struct sockaddr_in *yclient;
    struct dns_request *xdns_req;
    struct dns_request *dns_req;
};

//struct thread_info {    	/* Used as argument to thread_start() */
//    pthread_t thread_id;        /* ID returned by pthread_create() */
//    int       thread_num;       /* Application-defined thread # */
//    char     *argv_string;      /* From command-line argument */
//};

//void start_thread(pthread_t *mt)
//{
//    mystruct local_data = {};
//    mystruct *data = malloc(sizeof(*data));
//    *data = local_data;
//    pthread_create(mt, NULL, threadFunc,readParams);
//    //pthread_create(mt, NULL, threadFunc,data);
//    //ret = pthread_create(&pth[i],NULL,threadFunc,readParams);
//    //pthread_create(&pth[i],NULL,threadFunc,readParams);
//}

//static void *
//thread_start(void *arg)
//{
//    struct thread_info *tinfo = arg;
//    char *uargv, *p;
//
//   printf("Thread %d: top of stack near %p; argv_string=%s\n",
//            tinfo->thread_num, &p, tinfo->argv_string);
//
//   uargv = strdup(tinfo->argv_string);
//    if (uargv == NULL)
//        handle_error("strdup");
//
//   for (p = uargv; *p != '\0'; p++)
//        *p = toupper(*p);
//
//   return uargv;
//}

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

int DEBUG;

struct dns_request
{
    uint16_t transaction_id,
             questions_num,
             flags,
             qtype,
             qclass;
    char hostname[256],
             query[256];
    size_t hostname_len;
};  

struct dns_reponse
{
    size_t lenght;
    char *payload;
};

/* * usage */
void usage(void)
{
    fprintf(stderr, "\n dnsp %s\n"
                       " usage: dnsp -l [local_host] -h [proxy_host] -r [proxy_port] -w [webport] -s [lookup_script]\n\n"
                       " OPTIONS:\n"
                       "      -l\t\t Local server address\n"
                       "      -p\t\t Local server port\n"
                       "      -h\t\t Remote proxy address\n"
                       "      -r\t\t Remote proxy port\n"
                       "      -u\t\t Proxy username (optional)\n"
                       "      -k\t\t Proxy password (optional)\n"
                       "      -s\t\t Lookup script URL\n"
                       "      -w\t\t Webserver port (optional, default 80)\n"
                       "      -t\t\t Stack size in format 0x1000000 (MB)\n"
                       "      -v\t\t Enable juicy DEBUG logging\n"
                       "\n"
                       " Example: dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 -s https://www.fantuz.net/nslookup.php -t 0x1000000\n\n"
    ,VERSION);
    exit(EXIT_FAILURE);
}

/* * Prints an error message and exit */
void error(const char *msg)
{
    fprintf(stderr," *** %s: %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

/* * Prints debug messages */
void debug_msg(const char* fmt, ...)
{
    va_list ap;

    if (DEBUG) {
        fprintf(stdout, " [%d]> ", getpid());
        va_start(ap, fmt);
        vfprintf(stdout, fmt, ap); 
        va_end(ap);
    }
}

/* * Return the length of the pointed buffer */
size_t memlen(const char *buff)
{
    size_t len = 0;
    
    while (1) {
        if (buff[len] == 0) break;
        len ++;       
    }

    return len;
}

/* Parses the dns request and returns the pointer to dns_request struct. Returns NULL on errors */
struct dns_request *parse_dns_request(const char *udp_request, size_t request_len)
{
    struct dns_request *dns_req;
    
    dns_req = malloc(sizeof(struct dns_request));

    /* Transaction ID */
    dns_req->transaction_id = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8);
    udp_request+=2;
    
    /* Flags */
    dns_req->flags = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8);
    udp_request+=2;

    /* Questions num */
    dns_req->questions_num = (uint8_t)udp_request[1] + (uint16_t)(udp_request[0] << 8); 
    udp_request+=2;

    /* Skipping 6 not interesting bytes 
       uint16_t Answers number 
       uint16_t Records number 
       uint16_t Additionals records number 
    */
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
            free(dns_req);
	    printf("CORE: size issue in DNS request\n");
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

/*  * Builds and sends the dns response datagram */
void build_dns_reponse(int sd, struct sockaddr_in *yclient, struct dns_request *dns_req, const char *ip, int mode, size_t xrequestlen)
{
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
	 *qhostname, // = dns_req->hostname,
         *token,
         *pch,
	 *maxim,
         *response_ptr;
	 //*ppch,
	 //*typeq,
    int i, ppch;
    ssize_t bytes_sent;


    if (DEBUG) {
	    //printf("BUILD-xhostname-int				: %u\n", (uint32_t)strlen(xhostname));
	    printf("BUILD-req-query				: %s\n", dns_req->query);
	
	    printf("BUILD-yclient->sin_addr.s_addr		: %u\n", (uint32_t)(yclient->sin_addr).s_addr);
	    printf("BUILD-yclient->sin_port			: %u\n", (uint32_t)(yclient->sin_port));
	    printf("BUILD-yclient->sin_family			: %d\n", (uint32_t)(yclient->sin_family));
	    printf("BUILD-xrequestlen				: %d\n", (uint32_t)(xrequestlen));
	
	    //printf("BUILD-client->sa_family			: %u\n", (struct sockaddr)&xclient->sa_family);
	    //printf("BUILD-client->sa_data			: %u\n", (uint32_t)client->sa_data);
	    printf("BUILD-xsockfd				: %u\n", xsockfd);
	    printf("BUILD-sockfd				: %d\n", sockfd);
	    //printf("BUILD-hostname				: %s\n", qhostname);
	    //printf("build-qry =%s\n",(xdns_req->query));
	    printf("BUILD-hostname				: %s\n", dns_req->hostname);
    	    ////printf("build-host=%s\n",(char *)(xdns_req->hostname));
    	    ////printf("build-answ=%s\n", rip);
    	    ////printf("build-anmd=%d\n", DNS_MODE_ANSWER);
    }

    response = malloc (UDP_DATAGRAM_SIZE);
    bzero(response, UDP_DATAGRAM_SIZE);

    maxim = malloc (DNSREWRITE);
    bzero(maxim, DNSREWRITE);

    response_ptr = response;
    //maxim_ptr = maxim;

    /* Transaction ID */
    response[0] = (uint8_t)(dns_req->transaction_id >> 8);
    response[1] = (uint8_t)dns_req->transaction_id;
    response+=2;
    
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
    } else if (mode == DNS_MODE_ERROR) {
       /* DNS_MODE_ERROR should truncate message instead of building it up ...  */

        /* Server failure (0x8182), but what if we want NXDOMAIN (0x....) ???*/
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
	     * */

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
    }
        
    /* Authority RRs 0 */
    response[0] = 0x00;
    response[1] = 0x00;
    response+=2;
    
    /* Additional RRs 0 */
    response[0] = 0x00;
    response[1] = 0x00;
    response+=2;

    /* Query */
    strncat(response, dns_req->query, dns_req->hostname_len);
    //printf("BUILD-INSIDE-dns_req->query			: %s\n",(dns_req->query));
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
        
	if (dns_req->qtype == 0x0f) { //MX
        	response[0] = 0x00;
	        response[1] = 0x0f;
        	response+=2;
	} else if (dns_req->qtype == 0xFF) { //ALL
        	response[0] = 0x00;
	        response[1] = 0xFF;
        	response+=2;
	} else if (dns_req->qtype == 0x01) { //A
		*response++ = 0x00;
		*response++ = 0x01;
	} else if (dns_req->qtype == 0x05) { //CNAME
        	response[0] = 0x00;
	        response[1] = 0x05;
        	response+=2;
	} else if (dns_req->qtype == 0x0c) { //PTR
        	response[0] = 0x00;
	        response[1] = 0x0c;
        	response+=2;
	} else if (dns_req->qtype == 0x02) { //NS
        	response[0] = 0x00;
	        response[1] = 0x02;
        	response+=2;
	} else { return; }
        
        /* Class IN */
	*response++ = 0x00;
	*response++ = 0x01;

       	/* TTL (4 hours) */
	*response++ = 0x00;
	*response++ = 0x00;
	*response++ = 0x38;
	*response++ = 0x40;
	
	//ptr,ns
	if (dns_req->qtype == 0x0c || dns_req->qtype == 0x02) {
        
	        /* Data length (4 bytes)*/
	        response[0] = 0x00;
	        response[1] = 0x04;
	        response+=2;
		response[0] = 0xc0;
		response[1] = 0x0c;
	       	response+=2;

	} else if (dns_req->qtype == 0x05) { //CNAME RECORD

	        /* Data length (4 bytes)*/
        	response[0] = 0x00;
		response[1] = (strlen(ip)+1);
        	response+=2;

		pch = strtok((char *)ip,".\r\n\t");
		while (pch != NULL)
		{
			ppch = strlen(pch);
			*response++ = strlen(pch);
			for (i = 0; i < strlen(pch); ++i) {
				*response++ = pch[i];
				maxim[i] = pch[i];
			}
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

	} else if (dns_req->qtype == 0x0f) { //MX RECORD
	        /* Data length (4 bytes)*/
        	response[0] = 0x00;
		response[1] = (strlen(ip)+3);
		//response[1] = 0x00;
        	response+=2;

	        /* PRIO (4 bytes)*/
		response[0] = 0x00;
		response[1] = 0x0a;
        	response+=2;

	        /* POINTER, IF YOU ARE SO BRAVE OR ABLE TO USE IT (4 bytes) -> do not use label then... so you should re-write the code to have super-duper minimal responses. That code would also need domain comparison, to see if suffix can be appended */
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
		
	} else if (dns_req->qtype == 0x01) { // A RECORD 

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
        	//fprintf(stdout, "DNS_MODE_COMPLETE\n");
		
      	} else {
        	fprintf(stdout, "DNS_MODE_ISSUE\n");
		return;
	}
	//*response++=(unsigned char)(strlen(ip)+1);
	//memcpy(response,ip,strlen(ip)-1);
	//strncpy(response,ip,strlen(ip)-1);
    
	//recvfrom(3, "\326`\1 \0\1\0\0\0\0\0\1\6google\2it\0\0\1\0\1\0\0)\20\0"..., 256, 0, {sa_family=AF_INET, sin_port=htons(48379), sin_addr=inet_addr("192.168.2.84")}, [16]) = 38

	//(3, "\24\0\0\0\26\0\1\3\23\306;U\0\0\0\0\0\0\0\0", 20, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 20
	//(3, "z\271\205\200\0\1\0\1\0\0\0\0\6google\2hr\0\0\2\0\1\300\f\0\2\0"..., 41, 0, {sa_family=0x1a70 /* AF_??? */, sa_data="s\334\376\177\0\0\20D\1\270\223\177\0\0"}, 8)
	
	//(struct sockaddr *)xclient->sin_family = AF_INET;
	int yclient_len = sizeof(yclient);
        yclient->sin_family = AF_INET;
	//yclient->sin_addr.s_addr = inet_addr("192.168.2.84"); 
	//yclient->sin_port = htons(yclient->sin_port);
	yclient->sin_port = yclient->sin_port;
	memset(&(yclient->sin_zero), 0, sizeof(yclient->sin_zero)); // zero the rest of the struct 
	//memset(yclient, 0, 0);

	
    	if (DEBUG) {
	    	printf("BUILD-INSIDE-response				: %s\n", response);
		printf("BUILD-INSIDE-yclient->sin_addr.s_addr         	: %u\n", (uint32_t)(yclient->sin_addr).s_addr);
		printf("BUILD-INSIDE-yclient->sin_port                	: %u\n", (uint32_t)(yclient->sin_port));
		printf("BUILD-INSIDE-yclient->sin_port                	: %u\n", htons(yclient->sin_port));
		printf("BUILD-INSIDE-yclient->sin_family              	: %d\n", (uint32_t)(yclient->sin_family));
		printf("BUILD-INSIDE-dns-req->hostname			: %s\n", dns_req->hostname);
		printf("BUILD-INSIDE-dns_req->query			: %s\n", dns_req->query);
		printf("BUILD-INSIDE-xrequestlen			: %u\n", (uint16_t)xrequestlen);
	//	printf("BUILD-INSIDE-xdns_req->query			: %s\n", xdns_req->query);
	//	printf("BUILD-INSIDE-xdns_req->hostname-to-char		: %s\n", (char *)(xdns_req->hostname));
	//	printf("BUILD-INSIDE-xdns_req->hostname			: %s\n", xdns_req->hostname);
	//	printf("BUILD-INSIDE-xdns_req->query			: %s\n", xdns_req->query);
	}
        
	//bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)(&yclient), sizeof(yclient));
        bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)yclient, 16);
	//bytes_sent = sendto(3, "\270\204\205\200\0\1\0\1\0\0\0\0\6google\2jp\0\0\1\0\1\300\f\0\1\0"..., 43, 0, {sa_family=0x0002 /* AF_??? */, sa_data="\365\366\374\177\0\0\1\0\0\0\3\0\0\0"}, 16)

    } else if (mode == DNS_MODE_ERROR) {
    /* Are we into "No such name" ?... just an NXDOMAIN ?? */ 
        fprintf(stdout, "DNS_MODE_ERROR\n");
        bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)yclient, 16);
    } else {
        fprintf(stdout, "DNS_MODE_UNKNOWN\n");
        bytes_sent = sendto(sd, response_ptr, response - response_ptr, 0, (struct sockaddr *)yclient, 16);
    }
    /* DNS VOLUME CALCULATION */
    if (DEBUG) {
	printf("SENT %d bytes\n", (uint32_t)bytes_sent);
    }
    //fdatasync(sd);
    close(sd);
    free(response_ptr);
    free(dns_req);
    //free(ip);
}

/* * libCurl write data callback */
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t stream_size;
    stream_size = size * nmemb + 1;
    bzero(stream, HTTP_RESPONSE_SIZE);
    memcpy(stream, ptr, stream_size);
    return 0;
}

/* *  Hostname lookup *  Return: *   OK: Resolved IP *   KO: Null */
char *lookup_host(const char *host, const char *proxy_host, unsigned int proxy_port, const char *proxy_user, const char *proxy_pass, const char *lookup_script, const char *typeq, unsigned int wport)
{
    CURL *ch;
    CURLSH *curlsh;
    char *http_response,
         *script_url;
    int ret;
//    struct curl_slist *hosting = NULL;
    struct curl_slist *list = NULL;

    script_url = malloc(URL_SIZE);
    http_response = malloc(HTTP_RESPONSE_SIZE);
    bzero(script_url, URL_SIZE);
    
    snprintf(script_url, URL_SIZE-1, "%s?host=%s&type=%s", lookup_script, host, typeq);
    
    /* curl setup */
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_URL, script_url);
    curl_easy_setopt(ch, CURLOPT_PORT, wport); //80

    curl_easy_setopt(ch, CURLOPT_DNS_CACHE_TIMEOUT, 3600);
    curl_easy_setopt(ch, CURLOPT_DNS_USE_GLOBAL_CACHE, 1);	/* DNS CACHE  */
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);		/* No progress meter */

    if ((proxy_host != NULL) && (proxy_port > 0)) {
    	curl_easy_setopt(ch, CURLOPT_PROXY, proxy_host);
    	curl_easy_setopt(ch, CURLOPT_PROXYPORT, proxy_port);	/* 8118 */
    	curl_easy_setopt(ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    	/* optional proxy username and password */
    	if ((proxy_user != NULL) && (proxy_pass != NULL)) {
    	    curl_easy_setopt(ch, CURLOPT_PROXYUSERNAME, proxy_user);
    	    curl_easy_setopt(ch, CURLOPT_PROXYPASSWORD, proxy_pass);
    	}
    }

    curl_easy_setopt(ch, CURLOPT_VERBOSE,  0);			/* Verbose OFF */

    //curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0)
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);;


// curl -H "Host: www.fantuz.net" -H "Remote Address:217.114.216.51:80" -H "Request URL:http://www.fantuz.net/nslookup.php" -H "Host:www.fantuz.net" -H "User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36" http://www.fantuz.net/nslookup.php?host=fantuz.net

    /* try to see.... */
    //curl_easy_setopt(ch, CURLINFO_HEADER_OUT, "" );
    //curl_easy_setopt(ch, CURLOPT_HEADER, 1L);

    /*
    // OPTION --> add resolver & CURL headers
    CALLBACK TO PHP, BEHIND WHICH SITS THE "REAL" RESOLVER
    CAN BE HIDDEN BY MANUAL RESOLVE OVERRIDE, I.E.
    --resolve my.site.com:80:1.2.3.4, -H "Host: my.site.com"
    */

    //// OPTION --> HEADERS
    //    list = curl_slist_append(list, "Host: www.fantuz.net");
    //    list = curl_slist_append(list, "Remote Address: 217.114.216.51:80");
    //    list = curl_slist_append(list, "Request URL: http://www.fantuz.net/nslookup.php");
    //    list = curl_slist_append(list, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36");
    //    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, list);

    //hosting = curl_slist_append(hosting, "www.fantuz.net:80:217.114.216.51");
    //curl_easy_setopt(ch, CURLOPT_RESOLVE, hosting);

    /* HOW DOES A NEW TCP INFLUENCE WEB CACHE ?? */
    curl_easy_setopt(ch, CURLOPT_MAXCONNECTS, MAXCONN);
    curl_easy_setopt(ch, CURLOPT_FRESH_CONNECT, 0);
    curl_easy_setopt(ch, CURLOPT_FORBID_REUSE, 0);
    //curl_setopt ($curl, CURLOPT_AUTOREFERER, 1);

    //// OPTION --> FOLLOW-LOCATION
    //curl_setopt ($curl, CURLOPT_FOLLOWLOCATION, 1);

    /* Problem in performing the http request ?? */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, write_data);	/* Set write function */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, http_response);

    //CURL_LOCK_DATA_SHARE
    curlsh = curl_share_init();
    curl_easy_setopt(ch, CURLOPT_SHARE, curlsh);
    curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
    curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS); 

    ret = curl_easy_perform(ch);

    //if ((ret < 0) || (ret > 0)) {
    if (ret < 0) {
        debug_msg ("Error performing HTTP request (Error %d) - spot on !!!\n");
        printf("Error performing HTTP request (Error %d) - spot on !!!\n",ret);
        curl_easy_cleanup(ch);
	//curl_share_cleanup(curlsh);
        free(script_url);
	curl_slist_free_all(list);
//	//curl_slist_free_all(hosting);
        return NULL;
    }
   
    /* Can't resolve host */
    if ((strlen(http_response) > 256) || (strncmp(http_response, "0.0.0.0", 7) == 0)) {
	/* insert error answers here, as NXDOMAIN, SERVFAIL etc */
        printf("CORE: MALFORMED DNS, possible SERVFAIL from origin... investigate !\n");
        curl_easy_cleanup(ch);
        free(script_url);
	curl_slist_free_all(list);
//	curl_slist_free_all(hosting);
    	printf("inside curl (MALF) .... %s",http_response);
        http_response = "0.0.0.0\r\n";
        return NULL;
        //return http_response;
    }
   
    printf("inside curl .... %s",http_response);
    curl_easy_cleanup(ch);
    free(script_url);
    curl_slist_free_all(list);
//    curl_slist_free_all(hosting);
    return http_response;
}

/* This is our thread function.  It is like main(), but for a thread*/
void *threadFunc(void *arg)
{
	struct readThreadParams *params = (struct readThreadParams*)arg;

	struct dns_request *xdns_req = (struct dns_request *)params->xhostname;
	struct sockaddr_in *yclient = (struct sockaddr_in *)params->yclient;
	//struct sockaddr_in *xclient = (struct sockaddr_in *)params->xclient;
        struct dns_request *dns_req = malloc(sizeof(struct dns_request));
	struct dns_request *xhostname = (struct dns_request *)params->xhostname;
	size_t request_len = params->xrequestlen;
	//char *str;
	//int test = params->digit;
	//char* data = params->input;
	int wport = params->xwport;
	int proxy_port = params->xproxy_port;
	char* proxy_user = params->xproxy_user;
	char* proxy_pass = params->xproxy_pass;
	char* proxy_host = params->xproxy_host;
	char* lookup_script = params->xlookup_script;
	char* typeq = params->xtypeq;
	int xsockfd = params->xsockfd;
	int sockfd = params->sockfd;
	int ret;
	char *rip = malloc(256 * sizeof(char));
	char *ip = NULL;
	char *yhostname = (char *)params->xhostname->hostname;

	//pthread_key_t key_i;
        //pthread_key_create(&key_i, NULL);
	//str=(char*)arg;

/*
	//if (pthread_mutex_trylock(&mutex)) {
	if (pthread_mutex_lock(&mutex)) {
	    printf("init lock OK ... \n");
	} else {
	    printf("init lock NOT OK ... \n");
	}
*/

    	if (DEBUG) {
		
		//char *p = &xclient->sin_addr.s_addr;
		char *s = inet_ntoa(yclient->sin_addr);
		printf("test: %s\n",(char *)params->xhostname->hostname);
		printf("test: %s\n",(char *)params->xdns_req->hostname);
		printf("test: %s\n",(char *)xdns_req->hostname);
		printf("VARIABLE-RECV: %d\n", (uint32_t)(yclient->sin_addr).s_addr);
		printf("VARIABLE-RECV: %s\n", s);
		printf("VARIABLE-RECV: %s\n", lookup_script);
		printf("VARIABLE-RECV: %s\n", yhostname);
	}
	
        rip = lookup_host(yhostname, proxy_host, proxy_port, proxy_user, proxy_pass, lookup_script, typeq, wport);

	/* PTHREAD SET SPECIFIC GLOBAL VARIABLE ... */
	////pthread_setspecific(glob_var_key_ip, rip);

	if (DEBUG) {	
		printf("VARIABLE-RET-HTTP: %d", ret);
		printf("VARIABLE-RET-HTTP: %s", rip);
		//pthread_setspecific(glob_var_key_ip, rip);
		//pthread_getspecific(glob_var_key_ip);
// MOD 2015	printf("VARIABLE-RET-HTTP-GLOBAL: %x\n", glob_var_key_ip);
		//printf("VARIABLE-HTTP: %x\n", pthread_getspecific(glob_var_key_ip));
		//printf("build: %s", inet_ntop(AF_INET, &ip_header->saddr, ipbuf, sizeof(ipbuf)));
	}

	if ((rip != NULL) && (strncmp(rip, "0.0.0.0", 7) != 0)) {
	    if (DEBUG) {
		    printf("THREAD-V-ret				: [%d]\n",ret);
		    printf("THREAD-V-type				: %d\n", dns_req->qtype);
		    printf("THREAD-V-type				: %s\n", typeq);
		    printf("THREAD-V-size				: %u\n", (uint32_t)request_len);
		    printf("THREAD-V-socket-sockfd			: %u\n", sockfd);
		    printf("THREAD-V-socket-xsockfd			: %u\n", xsockfd);
		    printf("THREAD-V-socket-xsockfd			: %d\n", xsockfd);
		    printf("THREAD-V-MODE-ANSWER			: %d\n", DNS_MODE_ANSWER);
		    printf("THREAD-V-xclient->sin_addr.s_addr		: %u\n", (uint32_t)(yclient->sin_addr).s_addr);
		    printf("THREAD-V-xclient->sin_port			: %u\n", (uint32_t)(yclient->sin_port));
		    printf("THREAD-V-xclient->sin_family		: %u\n", (uint32_t)(yclient->sin_family));
		    printf("THREAD-V-answer				: %s\n", rip);
		    printf("THREAD-V-xhostname				: %s\n", yhostname);
		    printf("THREAD-V-dns-req->hostname			: %s\n", dns_req->hostname);
		    printf("THREAD-V-dns_req->query			: %s\n", dns_req->query);
		    printf("THREAD-V-dns_req->query			: %s\n", xdns_req->query);
		    printf("THREAD-V-xdns_req->hostname-to-char		: %s\n", (char *)(xdns_req->hostname));
		    printf("THREAD-V-xdns_req->hostname			: %s\n", xdns_req->hostname);
		    printf("THREAD-V-xdns_req->query			: %s\n", xdns_req->query);
	    }

            build_dns_reponse(sockfd, yclient, xhostname, rip, DNS_MODE_ANSWER, request_len);

	    //printf("THREAD-V-xclient->sin_addr.s_addr		: %s\n",(char *)(xclient->sin_family));
        } else if ( strstr(dns_req->hostname, "hamachi.cc") != NULL ) {
            printf("BALCKLIST: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, rip, (uint32_t)request_len);
	    printf("BLACKLIST: xsockfd %d - hostname %s \r\n", xsockfd, xdns_req->hostname);
	    printf("BLACKLIST: xsockfd %d - hostname %s \r\n", xsockfd, yhostname);
            build_dns_reponse(xsockfd, yclient, xhostname, rip, DNS_MODE_ANSWER, request_len);
        } else if ( rip == "0.0.0.0" ) {
       	    printf("ERROR: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, rip, (uint32_t)request_len);
	    printf("ERROR: xsockfd %d - hostname %s \r\n", xsockfd, yhostname);
	    printf("Generic resolution problem \n");
            build_dns_reponse(xsockfd, yclient, xhostname, rip, DNS_MODE_ERROR, request_len);
	}

	//char *s = inet_ntoa(xclient->sin_addr);
	//pthread_setspecific(glob_var_key_ip, NULL);

/*
	if (pthread_mutex_unlock(&mutex)) {
	    printf("unlock OK..\n");
	} else {
	    printf("unlock NOT OK..\n");
	} 

	pthread_mutex_destroy(&mutex);
	printf("destroy OK..\n");
*/
   	//printf("Thread/process ID : %d\n", getpid());
	//pthread_exit(NULL);
	exit(EXIT_SUCCESS);
}

/* *   main */
int main(int argc, char *argv[])
{
    int sockfd, port = DEFAULT_LOCAL_PORT, wport = DEFAULT_WEB_PORT, proxy_port = 0, c;
    int r = 0;
    struct sockaddr_in serv_addr;
    struct hostent *local_address;
    char *bind_address = NULL, *proxy_host = NULL, *proxy_user = NULL,
         *proxy_pass = NULL, *typeq = NULL, *lookup_script = NULL; 
    opterr = 0;
    DEBUG = 0;
       
    ////sem_t mutex;
    int s, tnum, opt, num_threads;
    //struct thread_info *tinfo;
    //pthread_attr_t attr;

    int stack_size;
    void *res;
    int thr = 0;
    int *ptr[2];

    /* The "-s" option specifies a stack size for our threads */
    stack_size = -1;

    /* Command line args */
    while ((c = getopt (argc, argv, "s:p:l:r:h:t:w:u:k:v::")) != -1)
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
                exit(EXIT_FAILURE);
            }
        break;

        case 'r':
            proxy_port = atoi(optarg);
            if (proxy_port <= 0) {
                fprintf(stdout," *** Invalid proxy port\n");
                exit(EXIT_FAILURE);
            }
        break;
                
        case 'v':
            DEBUG = 1;
        break;
        
        case 'l':
            bind_address = (char *)optarg;
        break;

        case 'h':
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
        abort ();
    }

    if ((port == 0) || (proxy_port == 0) || (bind_address == NULL) || (proxy_host == NULL) || (lookup_script == NULL))
        usage();

    /* Prevent child process from becoming zombie process */
    signal(SIGCLD, SIG_IGN);

    /* libCurl init */
    curl_global_init(CURL_GLOBAL_ALL);

    /* socket() */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    int socketid = 0;
    if (sockfd < 0) 
        error("Error opening socket");
    if ((socketid = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) err(1, "socket(2) failed");


    bzero((char *) &serv_addr, sizeof(serv_addr));
    local_address = gethostbyname(bind_address);

    if (local_address == NULL)
        error("Error resolving local host");
    
    serv_addr.sin_family = AF_INET;
    memcpy (&serv_addr.sin_addr.s_addr, local_address->h_addr,sizeof (struct in_addr));
    serv_addr.sin_port = htons(port);

    /* bind() */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
       error("Error opening socket (bind)");

//	if( sem_init(&mutex,1,1) < 0) {
//		perror("semaphore initilization"); exit(0);
//	}
    
/*
    if(pthread_mutex_init(&mutex, &MAttr))
    {
        printf("Unable to initialize a mutex\n");
        return -1;
    }
*/

    while (1) {

/*
    pthread_mutexattr_init(&MAttr);
    //pthread_mutexattr_settype(&MAttr, PTHREAD_MUTEX_ERRORCHECK);
    pthread_mutexattr_settype(&MAttr, PTHREAD_MUTEX_RECURSIVE);
*/

	//wait(NULL);
	int nnn = 0, i = 0;
	int s, tnum, opt;
	int stack_size;
	int rc, t, status;
	unsigned int request_len, client_len;

	char request[UDP_DATAGRAM_SIZE + 1], *ip = NULL;

	struct dns_request *dns_req;
	struct sockaddr client;
	//struct thread_info *tinfo;

	/* Initialize and set thread detached attribute */
	//pthread_id_np_t   tid;
	//tid = pthread_getthreadid_np();

//	pthread_t *pth = malloc( NUMT * sizeof(pthread_t) );			// this is our thread identifier
	//pthread_t *tid = malloc( NUMT * sizeof(pthread_t) );
	//pthread_t thread[NUM_THREADS];
	//static pthread_t tidd;

	//struct thread_data data_array[NUM_THREADS];
//	pthread_attr_t attr;
//	pthread_attr_init(&attr);
//	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	//pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    	//sem_wait(&mutex);  /* wrong ... DO NOT USE */
	//pthread_mutex_trylock(&mutex);

/*
	pthread_mutex_destroy(&mutex);
*/
   	client_len = sizeof(client);
   	request_len = recvfrom(sockfd,request,UDP_DATAGRAM_SIZE,0,(struct sockaddr *)&client,&client_len);

    	//wait(NULL);
        /* Child */
	if (fork() == 0) {
	    //sem_wait(&mutex);
   	    dns_req = parse_dns_request(request, request_len);

	    if (DEBUG) {
		    printf("\nSIZE OF REQUEST: %d", request_len);
	            printf("\nINFO: transaction %x - name %s - size %d \r\n", dns_req->transaction_id, dns_req->hostname, request_len);
	    }

            if (dns_req == NULL) {
        	//printf("BL: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, ip, request_len);
            	printf("\nINFO-FAIL: transaction: %x - name %s - size %d \r\n", dns_req->transaction_id, dns_req->hostname, request_len);
                exit(EXIT_FAILURE);
            }

	    if (dns_req->qtype == 0x02) {
		typeq = "NS";
	    } else if (dns_req->qtype == 0x0c) {
		typeq = "PTR";
	    } else if (dns_req->qtype == 0x05) {
		typeq = "CNAME";
	    } else if (dns_req->qtype == 0x01) {
		typeq = "A";
	    } else if (dns_req->qtype == 0x0f) {
		typeq = "MX";
	    } else { //{ dns_req->qtype == 0xff;} 
		printf("gotcha\n");}
	    /* CORE DNS LOOKUP IS MADE ONCE (via HTTP and nslookup.php) THEN CACHED INTO THE NETWORK (polipo, memcache ...)
	     IMPLEMENTS DOMAIN BLACKLISTING, AUTHENTICATION, SSL. PENDING MULTITHREADING. SOON, MAKE BETTER FILTER .. */

	    /* OPTION --> BUFFER SIZE */
	   // int sndbuf = 512;
	   // int rcvbuf = 512;
	   // int yes = 1;
	   // //setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffsize, sizeof(buffsize));
	   // setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(sndbuf));
	   // setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(rcvbuf));
	   // setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

	    int ret;
	    //int test = 42;
	    int xwport = wport;
	    int xsockfd;
	    //char* str = "maxnumberone";
	    int xproxy_port = proxy_port;
	    char* xproxy_user = NULL;
	    char* xproxy_pass = NULL;
	    char* xproxy_host = proxy_host;
	    char* xlookup_script = lookup_script;
	    char* xtypeq = typeq;

            struct dns_request *xhostname;
            struct sockaddr_in *xclient;
            struct sockaddr_in *yclient;
	    struct readThreadParams *readParams = malloc(sizeof(*readParams));
	    //	  readParams->max_req_client = 10;
	    //	  readParams->random = 0;
	    //	  readParams->ssl = 0;
	    //	  readParams->uselogin = 1;
	    readParams->xproxy_user = proxy_user;
	    readParams->xproxy_pass = proxy_pass;
	    readParams->xproxy_host = proxy_host;
	    readParams->xproxy_port = proxy_port;
	    readParams->xlookup_script = lookup_script;
	    readParams->xtypeq = typeq;
	    readParams->xwport = wport;
	    readParams->xhostname = (struct dns_request *)dns_req;
	    readParams->xdns_req = (struct dns_request *)&dns_req;
	    readParams->xsockfd = xsockfd;
	    readParams->sockfd = sockfd;
	    readParams->xclient = (struct sockaddr_in *)&client;
	    readParams->yclient = (struct sockaddr_in *)&client;
	    //readParams->input = str;
	    //readParams->digit = test;
	    readParams->xrequestlen = request_len;
	    //free(out_array);

	    //tinfo = calloc(NUMT, sizeof(struct thread_info));
	    //if (tinfo == NULL) handle_error("calloc");
	
	    //errore = pthread_create(&tid[i], NULL, threadFunc, &data_array[i]);
	    //if (i=sizeof(pth)) { i = 0 ;}

/*
	    if (pthread_mutex_trylock(&mutex)) {
		//ret = pthread_create(&pth[i],NULL,threadFunc,readParams);
		printf("lock OK ...\n");
	    } else {
		printf("lock NOT OK ...\n");
	    }
*/

	    threadFunc(readParams);
	    exit(EXIT_SUCCESS);
	    //ret = pthread_create(&pth[i],&attr,threadFunc,readParams);

	    //sem_wait(&mutex);
	    //sem_post(&mutex);

/*
	    for(r=0; r < NUMT*NUM_THREADS; r++) {
//	    	if(0 != ret) {
//			fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, ret);
//		        char *vvv = pthread_getspecific(glob_var_key_ip);
//		        printf("GLOBAL-FAIL-IP: %s\n", vvv);
//	    	} else {
//		        char *vvv = pthread_getspecific(glob_var_key_ip);
//		        printf("GLOBAL-SUCC-IP: %s\n", vvv);
//		}

	        pthread_join(pth[i],NULL);
		//pthread_join(pth[r],NULL);
	        //tidd = pthread_self();
	        //fprintf(stderr, "self r - %d \n",pthread_self(pth[i]));

		if (DEBUG) {
	            fprintf(stderr, "pth i - %d \n",(uint16_t)pth[i]);
	            fprintf(stderr, "pth r - %d \n",(uint16_t)pth[r]);
	   	    //printf("OUTSIDE-THREAD-resolved-address: %s\n",ip);
	   	    //printf("OUTSIDE-THREAD-resolved-address: %d\n",ret);
	   	    //printf("OUTSIDE-THREAD-resolved-address: %d\n",glob_var_key_ip);
	   	    //printf("OUTSIDE-THREAD-log: pid [%u] - hostname %s - size %d ip %s\r\n", ret, dns_req->hostname, request_len, ip);
		    printf("OUTSIDE-THREAD-log: size %d\n",request_len);
		    fprintf(stderr, "Finished joining thread i-> %d, nnn-> %d, r-> %d \n",i,nnn,r);
		}

	        i++;
	        nnn++;
	    }

*/

	    //if (nnn > NUMT*NUM_THREADS*4) {wait(NULL);}
   	    //printf("IF: Thread/process ID : %d\n", getpid());
//	    if (i != 0) { i=0;}
	    //pthread_mutex_destroy(&mutex);

	    //pthread_join(pth[i],NULL);
	    //continue;
	    //pthread_setspecific(glob_var_key_ip, NULL);
	}
	/*else {

	    nnn++;
	    / * RECOVERY FROM THREAD BOMB * /
   	    //printf("ELSE: Thread/process ID : %d\n", getpid());
	    //if (nnn > 32) {wait(NULL);}
	    continue;
	    //break;

////	    for(nnn=0; nnn< NUMT; nnn++) {
////	        //struct sockaddr_in *xclient = (struct sockaddr_in *)params->xclient;
////	    	//pthread_join(tid[i],(void**)&(ptr[i])); //, (void**)&(ptr[i]));
////	    	//printf("\n return value from last thread is [%d]\n", *ptr[i]);
            	//pthread_join(pth[i],NULL);
////	    }

/ * LOCKS AND MUTEXES * /
////	    pthread_mutex_lock(&mutex);
////	    if (pthread_mutex_unlock(&mutex)) {
////	        //printf("unlock OK.. but no RET\n");
////		continue;
////	    } else {
////	        printf("unlock NOT OK.. and no RET\n");
////	    } 
            //sem_destroy(&mutex);

/ * JOIN THREADS * /
//	    if(pthread_join(pth[i], NULL)) {
//	    	//fprintf(stderr, "Finished serving client %s on socket %u \n",(struct sockaddr_in *)&client->sin_addr.s_addr,sockfd);
//	    }

/ * LOCKS AND MUTEXES * /
	    //pthread_mutex_destroy(&mutex);
	    / * DO NOT USE * /
	    //sem_post(&mutex);

            //exit(EXIT_FAILURE);
	    //pthread_join(pth[i],NULL);
	    //pthread_exit(NULL);

	    / * NONSENSE CAUSE NO THREAD ANYMORE * /
//	    if (DEBUG) {fprintf(stderr, "Finished joining thread i-> %d, nnn-> %d \n",i,nnn);}
	} */
    }
}

