#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>

#define WOL_PORT 9

volatile sig_atomic_t stop = 0;

void handle_sigint(int sig) {
    (void)sig;
    stop = 1;
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int set_promiscuous_mode(const char *iface, int sock) {
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
        perror("ioctl SIOCGIFFLAGS");
        return -1;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        perror("ioctl SIOCSIFFLAGS");
        return -1;
    }
    return 0;
}

int create_arp_socket(const char *iface) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
        perror("setsockopt SO_BINDTODEVICE");
        close(sock);
        return -1;
    }
    if (set_promiscuous_mode(iface, sock) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

// Compute checksum (RFC 1071)
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int icmp_ping(const char *ip) {
    int pingsock;
    struct sockaddr_in addr;
    struct icmp icmp_hdr;
    char packet[64];
    struct timeval timeout = {1, 0}; // 1 second

    // Create raw socket
    if ((pingsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("socket");
        return -1;
    }

    // Set socket timeout
    setsockopt(pingsock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Target address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr.sin_addr);

    // ICMP header
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_id = getpid() & 0xFFFF;
    icmp_hdr.icmp_seq = 0;
    icmp_hdr.icmp_cksum = 0;

    // Fill packet
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
    memset(packet + sizeof(icmp_hdr), 0x42, sizeof(packet) - sizeof(icmp_hdr)); // payload
    icmp_hdr.icmp_cksum = checksum(packet, sizeof(packet));
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr)); // update with checksum

    // Send ICMP packet
    if (sendto(pingsock, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        perror("sendto");
        close(pingsock);
        return -1;
    }

    // Receive response
    char recv_buf[1024];
    while (1) {
        ssize_t len = recv(pingsock, recv_buf, sizeof(recv_buf), 0);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout
                close(pingsock);
                return 1;
            }
            perror("recv");
            close(pingsock);
            return -1;
        }

        struct ip *ip_hdr = (struct ip *)recv_buf;
        struct icmp *icmp_resp = (struct icmp *)(recv_buf + (ip_hdr->ip_hl << 2));

        if (icmp_resp->icmp_type == ICMP_ECHOREPLY &&
            icmp_resp->icmp_id == (getpid() & 0xFFFF)) {
            close(pingsock);
            return 0; // Host is alive
        }
    }

    close(pingsock);
    return 1;
}

void send_wol_packet(const char *iface, const unsigned char *mac, const char *broadcast_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        return;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
        perror("setsockopt SO_BINDTODEVICE");
        close(sock);
        return;
    }

    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        perror("setsockopt SO_BROADCAST");
        close(sock);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(WOL_PORT);
    addr.sin_addr.s_addr = inet_addr(broadcast_ip);

    unsigned char packet[102];
    memset(packet, 0xFF, 6); // 6 bytes of 0xFF
    for (int i = 0; i < 16; i++) {
        memcpy(&packet[6 + i * 6], mac, 6);
    }

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
    } else {
        printf("WOL packet sent\n");
    }

    close(sock);
}

int wait_for_arp_packet(int sock, unsigned char *buffer, size_t buflen) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    int ready = select(sock + 1, &fds, NULL, NULL, &timeout);
    if (ready < 0) {
        if (errno == EINTR && stop) {
            return -1;
        }
        perror("select");
        return 0;
    } else if (ready == 0) {
        return 0;
    }

    ssize_t len = recv(sock, buffer, buflen, 0);
    if (len < 0) {
        perror("recv");
        return 0;
    }
    return len;
}

int is_arp_request_for_target(unsigned char *buffer, ssize_t len, const char *target_ip) {
    if (len < (ssize_t)(sizeof(struct ether_header) + sizeof(struct ether_arp)))
        return 0;

    struct ether_header *eth = (struct ether_header *)buffer;
    if (ntohs(eth->ether_type) != ETH_P_ARP)
        return 0;

    struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ether_header));
    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST)
        return 0;

    struct in_addr target_addr;
    memcpy(&target_addr, arp->arp_tpa, sizeof(target_addr));

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_addr, ip_str, sizeof(ip_str));

    return strcmp(ip_str, target_ip) == 0;
}

int parse_mac(const char *mac_str, unsigned char *mac) {
    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; ++i)
        mac[i] = (unsigned char)values[i];
    return 0;
}

void run_loop(int sock, const char *iface, const char *target_ip, const unsigned char *wol_mac, const char *broadcast_ip) {
    printf("Listening for ARP requests for %s on %s...\n", target_ip, iface);

    while (!stop) {
        unsigned char buffer[2048];
        int len = wait_for_arp_packet(sock, buffer, sizeof(buffer));
        if (len < 0)
            break;
        if (len == 0)
            continue;

        if (is_arp_request_for_target(buffer, len, target_ip)) {
            if (icmp_ping(target_ip) == 0) {
                printf("Host %s is alive, not sending WOL.\n", target_ip);
                continue;
            }
            printf("ARP request detected for %s. Sending WOL...\n", target_ip);
            send_wol_packet(iface, wol_mac, broadcast_ip);
        }
    }
}

int main(int argc, char *argv[]) {
    char *iface = NULL;
    char *target_ip = NULL;
    char *wol_mac_str = NULL;
    char *broadcast_ip = NULL;
    unsigned char wol_mac[6];

    static struct option long_options[] = {
        {"iface", required_argument, 0, 0},
        {"target-ip", required_argument, 0, 0},
        {"wol-mac", required_argument, 0, 0},
        {"wol-broadcast", required_argument, 0, 0},
        {0, 0, 0, 0}};

    int opt, opt_idx = 0;
    while ((opt = getopt_long(argc, argv, "", long_options, &opt_idx)) != -1) {
        if (opt == 0) {
            if (strcmp(long_options[opt_idx].name, "iface") == 0) {
                iface = optarg;
            }
            else if (strcmp(long_options[opt_idx].name, "target-ip") == 0) {
                target_ip = optarg;
            }
            else if (strcmp(long_options[opt_idx].name, "wol-mac") == 0) {
                wol_mac_str = optarg;
            }
            else if (strcmp(long_options[opt_idx].name, "wol-broadcast") == 0) {
                broadcast_ip = optarg;
            }
        }
    }

    if (!iface || !target_ip || !wol_mac_str || !broadcast_ip) {
        printf("Usage: %s --iface <iface> --target-ip <target_ip> --wol-mac <mac_str> --wol-broadcast <broadcast_ip>\n", argv[0]);
        return 1;
    }

    if (parse_mac(wol_mac_str, wol_mac) != 0) {
        fprintf(stderr, "Invalid MAC address format: %s\n", wol_mac_str);
        return 1;
    }

    setup_signal_handler();

    int sock = create_arp_socket(iface);
    if (sock < 0)
        return 1;

    run_loop(sock, iface, target_ip, wol_mac, broadcast_ip);

    printf("Exiting...\n");
    close(sock);
    return 0;
}
