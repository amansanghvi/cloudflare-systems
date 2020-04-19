#include <stdio.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>


#define PORT 0
#define ICMP_TYPE 8
#define ICMP_RES_TYPE 69
#define ECHO_CODE 0

struct icmp_header {
    uint64_t type: 8;
    uint64_t code: 8;
    uint64_t checksum: 16;
    uint64_t id: 16; // Should be zeroed for echo.
    uint64_t seq: 16;
};

struct icmp_packet {
    struct icmp_header header;
    char msg[16];
};

int get_sock_addr(char *hostname, int timeout, struct sockaddr_in *sock_addr);
int get_socket(int timeout);
void init_pkt(struct icmp_packet *pkt, uint16_t seq);
uint16_t checksum(struct icmp_packet *header);

uint16_t poll = 1;

void exit_ping(int err) {
    poll = 0;
}

int main(int argc, char *argv[]) {
    // Validating input
    if (argc != 2 && argc != 3) {
        printf("Invalid number of arguments. ");
        printf("Usage %s IP_ADDRESS\n", argv[0]);
        return EXIT_FAILURE; 
    }
    
    char *hostname = argv[1];
    int timeout = argc == 3 ? atoi(argv[2]) : 1;
    struct sockaddr_in sock_addr;
    if (get_sock_addr(hostname, timeout, &sock_addr) != 0) {
        printf("Getting socket failed\n");
        return EXIT_FAILURE;
    }

    int sock = get_socket(timeout);
    if (sock < 0) {
        printf("Socket not created.");
        return EXIT_FAILURE;
    }

    // Creating ping packet
    struct icmp_packet pkt;
    struct timespec start_time;
    struct timespec end_time;
    struct sockaddr_in recv_addr;
    uint32_t recv_len = sizeof(recv_addr);
    uint16_t seq = 0;
    double avg_ms = 0;
    uint16_t lost_pkts = 0;
    
    signal(SIGINT, exit_ping); // On ctrl-c
    
    while (poll) {
        sleep(1);
        init_pkt(&pkt, seq);
        clock_gettime(CLOCK_REALTIME, &start_time);

        if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) <= 0) {
            printf("Unable to send packet\n");
        } else {
            if (recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&recv_addr, &recv_len) <= 0) {
                lost_pkts++;
                printf("Request timed out, packet_loss=%d%%\n", 100*lost_pkts/(lost_pkts+seq));
            } else {
                if (pkt.header.code != ECHO_CODE || pkt.header.type != ICMP_RES_TYPE) {
                    printf("Invalid ICMP response with code: %d and type: %d\n", pkt.header.type, pkt.header.code);
                } else {
                    clock_gettime(CLOCK_REALTIME, &end_time);
                    double dt_ms = (end_time.tv_nsec - start_time.tv_nsec)/1e6 + (end_time.tv_sec - start_time.tv_sec)*1e3;
                    avg_ms = (avg_ms*seq + dt_ms)/(seq + 1);
                    printf("seq=%d, rtt=%.3fms, packet_loss=%d%%\n", seq, dt_ms, 100*lost_pkts/(lost_pkts+seq+1));
                    seq++;
                }
            }
        }
    }

    printf("recv_pkts=%d, rtt=%.3fms, packet_loss=%d%%\n", seq, avg_ms, 100*lost_pkts/(lost_pkts+seq));
    return EXIT_SUCCESS;
}

int get_sock_addr(char *hostname, int timeout, struct sockaddr_in *sock_addr) {
    struct hostent *dest = gethostbyname(hostname);
    if (dest == NULL) {
        printf("Invalid hostname: %s\n", hostname);
        return 1;
    }

    sock_addr->sin_family = dest->h_addrtype;
    sock_addr->sin_port = htons(PORT);
    sock_addr->sin_addr.s_addr = *(uint32_t *)dest->h_addr;

    char *dest_ip = inet_ntoa(*((struct in_addr*) dest->h_addr_list[0]));
    printf("Going to ping: %s\n", dest_ip);
    return 0;
}

int get_socket(int timeout) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        printf("Unable to create socket. Try running with sudo.\n");
        return -1;
    }
    struct timeval timeout_opt;
    timeout_opt.tv_sec = timeout; // set exactly to timeout seconds.
    timeout_opt.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,  (const void*)&timeout_opt, sizeof(timeout_opt)) < 0) {
        printf("Unable to setsockopt timeout\n");
    }
    return sock;
}

void init_pkt(struct icmp_packet *pkt, uint16_t seq) {
    memset(pkt, 0, sizeof(struct icmp_packet));
    
    pkt->header.code = ECHO_CODE;
    pkt->header.type = ICMP_TYPE;
    pkt->header.id = (uint16_t)getpid();
    pkt->header.seq = seq;
    strcpy(pkt->msg, "Hello world");
    pkt->header.checksum = checksum(pkt);
}

// Sort of copied from offical doc: http://www.faqs.org/rfcs/rfc1071.html
uint16_t checksum(struct icmp_packet *header) {
    // Sum 16 bits at a time
    int count = sizeof(struct icmp_packet);
    uint16_t *curr_seg = (uint16_t *)header; 
    uint32_t chk_sum = 0;
  
    // Iterate over 64 bits
    while (count > 1)  {
        chk_sum += *(uint16_t *)curr_seg;
        curr_seg++; count -= 2;
    }
    if( count > 0 ) {
        chk_sum += * (uint8_t *)curr_seg;
    }
    // while more that 16 bits in number
    while (chk_sum >> 16) {
        // Add additional bits to the start
        chk_sum = (chk_sum & 0xFFFF) + (chk_sum >> 16);
    }
    return ~chk_sum; 
}
