/*
 * DNS proxy 0.5
 *  
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
 *
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

#define MAXCONN             500
#define UDP_DATAGRAM_SIZE   1024
#define HTTP_RESPONSE_SIZE  1024
#define URL_SIZE            256
#define VERSION             "0.5"
#define DNS_MODE_ANSWER     1
#define DNS_MODE_ERROR      2
#define DEFAULT_LOCAL_PORT  53

int DEBUG;

struct dns_request
{
    uint16_t transaction_id,
             questions_num,
             flags,
             qtype,
             qclass;
    char hostname[128],
         query[128];
    size_t hostname_len;
};  

struct dns_reponse
{
    size_t lenght;
    char *payload;
};

/*
 * usage
 */
void usage(void)
{
    fprintf(stderr, "\n dnsp %s\n"
                       " usage: dnsp -l [local_host] -h [proxy_host] -r [proxy_port] -s [lookup_script]\n\n"
                       " OPTIONS:\n"
                       "      -v\t\t Enable DEBUG mode\n"
                       "      -p\t\t Local port\n"
                       "      -l\t\t Local host\n"
                       "      -r\t\t Proxy port\n"
                       "      -h\t\t Proxy host\n"
                       "      -u\t\t Proxy username (optional)\n"
                       "      -k\t\t Proxy password (optional)\n"
                       "      -s\t\t Lookup script URL\n"
                       "\n"
                       " Example: dnsp -l 127.0.0.1 -h 10.0.0.2 -r 8080 -s http://www.andreafabrizi.it/nslookup.php\n"
    ,VERSION);
    exit(EXIT_FAILURE);
}

/*
 * Prints an error message and exit 
 */
void error(const char *msg)
{
    fprintf(stderr," *** %s: %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

/*
 * Prints debug messages
 */
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

/*
 * Return the length of the pointed buffer
 */
size_t memlen(const char *buff)
{
    size_t len = 0;
    
    while (1) {
        if (buff[len] == 0) break;
        len ++;       
    }

    return len;
}

/*
 * Parses the dns request
 * and returns the pointer to dns_request struct
 * Returns NULL on errors
 */
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

/*  
 * Builds and sends the dns response datagram 
 */
void build_dns_reponse(int sd, struct sockaddr_in client, struct dns_request *dns_req, const char *ip, int mode)
{
    char *response,
         *response_ptr,
         *token;
    ssize_t bytes_sent;
    
    response = malloc (UDP_DATAGRAM_SIZE);
    bzero(response, UDP_DATAGRAM_SIZE);
    response_ptr = response;

    /* Transaction ID */
    response[0] = (uint8_t)(dns_req->transaction_id >> 8);
    response[1] = (uint8_t)dns_req->transaction_id;
    response+=2;
    
    if (mode == DNS_MODE_ANSWER) {
        /* Default flags for a standard query (0x8580) */
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
    /* DNS_MODE_ERROR */
    else {
        /* Server failure (0x8182) */
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
        /* Pointer to host name */
        response[0] = 0xc0;
        response[1] = 0x0c;
        response+=2;
        
        /* Type A */
        response[0] = 0x00;
        response[1] = 0x01;     
        response+=2;
        
        /* Class IN */
        response[0] = 0x00;
        response[1] = 0x01;          
        response+=2;
        
        /* TTL (1 ora) */
        response[0] = 0x00;
        response[1] = 0x00;    
        response[2] = 0x0e;
        response[3] = 0x10; 
        response+=4;
        
        /* Data lenght (4 bytes)*/
        response[0] = 0x00;
        response[1] = 0x04;    
        response+=2;
        
        /* IP */
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
        
        bytes_sent = sendto(sd,response_ptr,response - response_ptr,0,(struct sockaddr *)&client,sizeof(client));
        fsync(sd);
    }
    
    /* No such name */
    else {
        bytes_sent = sendto(sd,response_ptr,response - response_ptr,0,(struct sockaddr *)&client,sizeof(client));
        fsync(sd);
    }
    
    debug_msg("Dns response sent to client (%d bytes)\n", bytes_sent);
    
    free(response_ptr);
}

/*
 * libCurl write data callback
 */
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t stream_size;
    
    stream_size = size * nmemb + 1;
    bzero(stream, HTTP_RESPONSE_SIZE);
    memcpy(stream, ptr, stream_size);

    return 0;
}

/*
 *  Hostname lockup
 *  Return:
 *   OK: Resolved IP
 *   KO: Null
 */
char *lookup_host(const char *host, const char *proxy_host, unsigned int proxy_port, const char *proxy_user, const char *proxy_pass, const char *lookup_script)
{
    CURL *ch;
    char *http_response,
         *script_url;
    int ret;
    
    script_url = malloc(URL_SIZE);
    http_response = malloc(HTTP_RESPONSE_SIZE);
    bzero(script_url, URL_SIZE);
    snprintf(script_url, URL_SIZE-1, "%s/?host=%s", lookup_script, host);
    
    /* curl setup */
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_URL, script_url);
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L); /* No progress meter */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, write_data); /* Set write function */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, http_response);
    curl_easy_setopt(ch, CURLOPT_PROXY, proxy_host);
    curl_easy_setopt(ch, CURLOPT_PROXYPORT, proxy_port);
    curl_easy_setopt(ch, CURLOPT_PROXYTYPE,  CURLPROXY_HTTP);
    curl_easy_setopt(ch, CURLOPT_VERBOSE,  0); /* Verbose OFF */

    /* option proxy username and password */
    if ((proxy_user != NULL) && (proxy_pass != NULL)) {
        curl_easy_setopt(ch, CURLOPT_PROXYUSERNAME, proxy_user);
        curl_easy_setopt(ch, CURLOPT_PROXYPASSWORD, proxy_pass);
    }

    /* Performing http request */
    ret = curl_easy_perform(ch);    
    if (ret < 0) {
        curl_easy_cleanup(ch);
        free(script_url);
        free(http_response);
        debug_msg ("Error performing http request (Error %d)\n");
        return NULL;
    }
   
    debug_msg("HTTP Response: '%s'\n", http_response);
   
    /* Can't resolve host */
    if ((strlen(http_response) > 16) || (strncmp(http_response, "0.0.0.0", 7) == 0)) {
        curl_easy_cleanup(ch);
        free(script_url);
        free(http_response);
        return NULL;
    }
   
    curl_easy_cleanup(ch);
    free(script_url);
    
    return http_response;
}

/*
 *   main
 */
int main(int argc, char *argv[])
{
    int sockfd, 
        port = DEFAULT_LOCAL_PORT,
        proxy_port = 0,
        c;
    struct sockaddr_in serv_addr;
    struct hostent *local_address;
    char *bind_address = NULL,
         *proxy_host = NULL,
         *proxy_user = NULL,
         *proxy_pass = NULL,
         *lookup_script = NULL;

    opterr = 0;
    DEBUG = 0;
       
    /* Command line args */
    while ((c = getopt (argc, argv, "s:p:l:r:h:u:k:v::")) != -1)
    switch (c)
    {
        case 'p':
            port = atoi(optarg);
            if (port <= 0) {
                fprintf(stdout," *** Invalid local port\n");
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
            if (optopt == 'r')
                fprintf(stderr," *** Invalid proxy port\n");
            else 
            if (optopt == 's')
                fprintf(stderr," *** Invalid lockup script URL\n");
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

    debug_msg("Starting DNS proxy v%s (DEBUG mode enabled!)\n", VERSION);
    
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

        debug_msg("New udp datagram from client (%d bytes)\n", request_len);
    
        /* Child */
        if (fork() == 0)
        {
            dns_req = parse_dns_request(request, request_len);
            if (dns_req == NULL) {
                debug_msg("Error parsing UDP datagram\n");
                exit(EXIT_FAILURE);
            }
            debug_msg("Transaction id: 0x%x\n", dns_req->transaction_id);
            debug_msg("Hostname: %s\n", dns_req->hostname);

            /* Please, don't resolve the matching hosts :) */
            if (strstr(dns_req->hostname, ".example.com") == NULL) {
                ip = lookup_host(dns_req->hostname, proxy_host, proxy_port, proxy_user, proxy_pass, lookup_script);
                if (ip != NULL) {
                    debug_msg("Hostname resolved: %s\n", ip);
                    build_dns_reponse(sockfd, client, dns_req, ip, DNS_MODE_ANSWER);
                    free(ip);
                }
                else {
                    debug_msg("Error resolving host: %s\n", dns_req->hostname);
                    build_dns_reponse(sockfd, client, dns_req, ip, DNS_MODE_ERROR);
                }
            }
            else {
                debug_msg("Hostname blacklisted!\n");
                build_dns_reponse(sockfd, client, dns_req, ip, DNS_MODE_ERROR);
            }

            free(dns_req);
            exit(EXIT_SUCCESS);
        }
    }
    
}

	
