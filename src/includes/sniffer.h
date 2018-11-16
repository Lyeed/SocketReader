#ifndef sniffer_h
#define sniffer_h

#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <gtk/gtk.h>

typedef enum protocol_e {
  TCP = 1,
  UDP = 2,
  ICMP = 3,
  ARP = 4,
  HTTP = 5,
  DNS = 6,
  Unknown = 0
} protocol_t;

typedef struct ethernet_header_s {
  char *src_addr;
  char *dest_addr;
  unsigned short proto;
} ethernet_header_t;

typedef struct ip_header_s {
  unsigned int version;
  unsigned int header_len; //en octet
  unsigned int service_type;
  unsigned short total_len;
  unsigned short id;
  unsigned int ttl;
  unsigned int proto;
  unsigned short checksum;
  char *src_ip;
  char *dest_ip;
} ip_header_t;

//HTTP port=80 == TCP
typedef struct tcp_header_s {
  unsigned short src_port;
  unsigned short dest_port;
  unsigned long seq;
  unsigned long ack_seq;
  unsigned int len;
  unsigned int urg;
  unsigned int ack;
  unsigned int push;
  unsigned int reset;
  unsigned int sync;
  unsigned int fin;
  unsigned short window;
  unsigned short checksum;
  int urg_ptr;
} tcp_header_t;

//DNS port=53 == UDP
typedef struct udp_header_s {
  unsigned short src_port;
  unsigned short dest_port;
  unsigned short len;
  unsigned short checksum;
} udp_header_t;

typedef struct icmp_header_s {
  unsigned int type;
  unsigned int code;
  unsigned short checksum;
} icmp_header_t;

typedef struct arp_header_s {
  unsigned short hrdw_f;
  unsigned short proto_f;
  unsigned char hrdw_len;
  unsigned char proto_len;
  unsigned short op;
} arp_header_t;

typedef struct info_packet_s {
  tcp_header_t *tcp;
  udp_header_t *udp;
  icmp_header_t *icmp;
  arp_header_t *arp;
} info_packet_t;

typedef struct data_dump_s {
  char *hexa;
  char *ascii;
} data_dump_t;

typedef struct raw_packet_s {
  guint num;
  double time;
  int length;
  protocol_t proto;
  ethernet_header_t *eth;
  ip_header_t *ip;
  info_packet_t *info;
  data_dump_t *dump;
  struct raw_packet_s *next;
  struct raw_packet_s *prev;
} raw_packet_t;

void *sniffer(void *);
void print_raw(const raw_packet_t *);
char *getProtocol(const int);
char *getInfo(const raw_packet_t *);
char *getBigDetails(const raw_packet_t *);
char *getHexa(const raw_packet_t *);
char *getAscii(const raw_packet_t *);
char *getAddrSource(const raw_packet_t *);
char *getAddrDest(const raw_packet_t *);
void import_pcapfile(const char *);
void export_pcapfile(const char *);
raw_packet_t *getPacket(const guint);

#endif
