/*
 * DNS proxy 0.99
 *  
 * Copyright (C) 2014 Massimiliano Fantuzzi <superfantuz@gmail.com>
 * Copyright (C) 2009-2013 Andrea Fabrizi <andrea.fabrizi@gmail.com>
 *  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
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

#ifndef SIGCLD
#   define SIGCLD SIGCHLD
#endif

#define DELAY		    500
#define MAXCONN             4096
#define UDP_DATAGRAM_SIZE   255
#define DNSREWRITE          255
#define HTTP_RESPONSE_SIZE  255
#define URL_SIZE            255
#define VERSION             "0.99"
#define DNS_MODE_ANSWER     1
#define DNS_MODE_ERROR      2
#define DEFAULT_LOCAL_PORT  53
#define DEFAULT_WEB_PORT    80
//#define TYPEQ		    2

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
                       "      -l\t\t Local server host\n"
                       "      -p\t\t Local server port\n"
                       "      -h\t\t Remote proxy host\n"
                       "      -r\t\t Remote proxy port\n"
                       "      -u\t\t Proxy username (optional)\n"
                       "      -k\t\t Proxy password (optional)\n"
                       "      -s\t\t Lookup script URL\n"
                       "      -w\t\t Webserver port (optional, default 80)\n"
                       "      -v\t\t Enable DEBUG mode\n"
                       "\n"
                       " Example: dnsp -p 53 -l 127.0.0.1 -h 127.0.0.1 -r 8118 -w 80 -s http://www.fantuz.net/nslookup.php\n\n"
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

/* * Parses the dns request and returns the pointer to dns_request struct Returns NULL on errors */
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
void build_dns_reponse(int sd, struct sockaddr_in client, struct dns_request *dns_req, const char *ip, int mode)
{
    char *response,
         *token,
         *pch,
	 *maxim,
	 //*ppch,
	 //*typeq,
         *response_ptr;
    int i, ppch;
    ssize_t bytes_sent;
    
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
	/* authoritative answer... or not ? :) */
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
    }
    /* DNS_MODE_ERROR should truncate message instead of building it up ...  */
    else {
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
		
      	} else { return;}
	//	*response++=(unsigned char)(strlen(ip)+1);
	//memcpy(response,ip,strlen(ip)-1);
	//strncpy(response,ip,strlen(ip)-1);
        bytes_sent = sendto(sd,response_ptr,response - response_ptr,0,(struct sockaddr *)&client,sizeof(client));
        //fdatasync(sd);
        close(sd);

    } else {

    /* Are we into "No such name" ?... just an NXDOMAIN ?? */ 
    //if (mode == DNS_MODE_ERROR)
        bytes_sent = sendto(sd,response_ptr,response - response_ptr,0,(struct sockaddr *)&client,sizeof(client));
        //fdatasync(sd);
	close(sd);
    }
    // DNS VOLUME CALCULATION
    //debug_msg("Dns response sent to client (DEC %d bytes)\n", bytes_sent);
    free(response_ptr);
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
    script_url = malloc(URL_SIZE);
    http_response = malloc(HTTP_RESPONSE_SIZE);
    bzero(script_url, URL_SIZE);
    
    //CALLBACK TO PHP, BEHIND WHICH SITS THE "REAL" RESOLVER
    snprintf(script_url, URL_SIZE-1, "%s?host=%s&type=%s", lookup_script, host, typeq);

    /* curl setup */
    ch = curl_easy_init();
    curlsh = curl_share_init();
    curl_easy_setopt(ch, CURLOPT_URL, script_url);
    curl_easy_setopt(ch, CURLOPT_PORT, wport); //80
    //curl_easy_setopt(ch, CURLINFO_HEADER_OUT, "" );
    curl_easy_setopt(ch, CURLOPT_DNS_CACHE_TIMEOUT, 900);
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L); /* No progress meter */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, write_data); /* Set write function */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, http_response);
    curl_easy_setopt(ch, CURLOPT_PROXY, proxy_host);
    curl_easy_setopt(ch, CURLOPT_PROXYPORT, proxy_port); //8118
    curl_easy_setopt(ch, CURLOPT_PROXYTYPE,  CURLPROXY_HTTP);
    curl_easy_setopt(ch, CURLOPT_VERBOSE,  0); /* Verbose OFF */
    curl_easy_setopt(ch, CURLOPT_DNS_USE_GLOBAL_CACHE, 0); /* DNS CACHE  */
    curl_easy_setopt(ch, CURLOPT_MAXCONNECTS, 16);
    curl_easy_setopt(ch, CURLOPT_FRESH_CONNECT, 0); /* HTTP CACHE  */
    curl_easy_setopt(ch, CURLOPT_FORBID_REUSE, 1);
//curl_setopt ($curl, CURLOPT_AUTOREFERER, 1);
//curl_setopt ($curl, CURLOPT_FOLLOWLOCATION, 1);

    //CURL_LOCK_DATA_SHARE
    //    curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
    curl_share_setopt(curlsh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS); 
    curl_easy_setopt(ch, CURLOPT_SHARE, curlsh);

/* PROXY AUTH REMOVED; just uncomment to enable !! */
/* option proxy username and password */
//    if ((proxy_user != NULL) && (proxy_pass != NULL)) {
//        curl_easy_setopt(ch, CURLOPT_PROXYUSERNAME, proxy_user);
//        curl_easy_setopt(ch, CURLOPT_PROXYPASSWORD, proxy_pass);
//    }


    /* Problem in performing http request */
    ret = curl_easy_perform(ch);    
    if (ret < 0) {
//	curl_share_cleanup(curlsh);
        debug_msg ("Error performing HTTP request (Error %d) - spot on !!!\n");
        curl_easy_cleanup(ch);
        free(script_url);
        free(http_response);
        return NULL;
    }
   
    /* Can't resolve host */
    //if ((strlen(http_response) > 16) || (strncmp(http_response, "0.0.0.0", 7) == 0)) {
    if ((strlen(http_response) > 256) || (strncmp(http_response, "0.0.0.0", 7) == 0)) {
	/* insert error answers here, as NXDOMAIN, SERVFAIL etc */
        debug_msg ("MALFORMED DNS, or SERVFAIL from origin... investigate !\n");
        curl_easy_cleanup(ch);
        free(script_url);
        free(http_response);
        return NULL;
    }
   
    curl_easy_cleanup(ch);
    free(script_url);
    return http_response;
}

/* *   main */
int main(int argc, char *argv[])
{
    int sockfd, 
        port = DEFAULT_LOCAL_PORT,
        wport = DEFAULT_WEB_PORT,
        proxy_port = 0,
        c;
    struct sockaddr_in serv_addr;
    struct hostent *local_address;
    char *bind_address = NULL,
         *proxy_host = NULL,
         *proxy_user = NULL,
         *proxy_pass = NULL,
	 *typeq = NULL,
         *lookup_script = NULL;

    opterr = 0;
    DEBUG = 0;
       
    /* Command line args */
    while ((c = getopt (argc, argv, "s:p:l:r:h:w:u:k:v::")) != -1)
    switch (c)
    {
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
            if (isprint(optopt))
                fprintf(stderr," *** Invalid option -- '%c'\n", optopt);
                
            usage();
        break;
        
        default:
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
    if (sockfd < 0) 
        error("Error opening socket");

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
    
    while (1) {
        char request[UDP_DATAGRAM_SIZE + 1],
             *ip = NULL;
        unsigned int request_len,
                     client_len;
        struct dns_request *dns_req;
        struct sockaddr_in client;
        
        client_len = sizeof(client);
        request_len = recvfrom(sockfd,request,UDP_DATAGRAM_SIZE,0,(struct sockaddr *)&client,&client_len);

        /* Child */
        if (fork() == 0)
        {
            dns_req = parse_dns_request(request, request_len);
            if (dns_req == NULL) {
        	//printf("BL: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, ip, request_len);
            	printf("FORK: tid: %x - name %s - size %d \r\n", dns_req->transaction_id, dns_req->hostname, request_len);
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
	    } //else { dns_req->qtype == 0xff;} 
//

//	CORE DNS LOOKUP, MADE ONCE (via HTTP)AND THEN CACHED BY POLIPO... MEMCACHED... OR OTHER DAEMONS
//	WITH DOMAIN BLACKLISTING

    	    //int buffsize = 2048;
    	    //setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffsize, sizeof(buffsize));
            ip = lookup_host(dns_req->hostname, proxy_host, proxy_port, proxy_user, proxy_pass, lookup_script, typeq, wport);

            if (ip != NULL) {
            //if (ip != NULL && ip != "0.0.0.0") {
            //if (ip != NULL && ((strstr(dns_req->hostname, "bbc.com") == NULL ) || (strstr(dns_req->hostname, "skype.com") == NULL )) ) {
                build_dns_reponse(sockfd, client, dns_req, ip, DNS_MODE_ANSWER);
                free(ip);
            } else if (strstr(dns_req->hostname, "hamachi.cc") != NULL ) {
        	printf("BALCKLIST: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, ip, request_len);
                build_dns_reponse(sockfd, client, dns_req, ip, DNS_MODE_ANSWER);
         	free(ip);
            } else {
       	        printf("ERROR: pid [%d] - name %s - host %s - size %d \r\n", getpid(), dns_req->hostname, ip, request_len);
                build_dns_reponse(sockfd, client, dns_req, ip, DNS_MODE_ERROR);
         	free(ip);
}

            free(dns_req);
            exit(EXIT_SUCCESS);
        }
    }
}
