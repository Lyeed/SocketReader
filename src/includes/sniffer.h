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
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>

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

typedef struct info_packet_s {
  tcp_header_t *tcp;
  udp_header_t *udp;
  icmp_header_t *icmp;
} info_packet_t;

typedef struct data_dump_s {
  char *hexa;
  char *ascii;
} data_dump_t;

typedef struct raw_packet_s {
  int num;
  float time;
  protocol_t proto;
  ethernet_header_t *eth;
  ip_header_t *ip;
  info_packet_t *info;
  data_dump_t *dump;
  struct raw_packet_s *next;
  struct raw_packet_s *prev;
} raw_packet_t;

void *sniffer(void *);
void fill_raw_packet(raw_packet_t **, unsigned char *, int, int);
void fill_ethernet_header(raw_packet_t **, unsigned char *);
void fill_ip_header(raw_packet_t **, unsigned char *);
void fill_info_header(raw_packet_t **, unsigned char *);
void fill_info_icmp(raw_packet_t **, unsigned char *);
void fill_info_tcp(raw_packet_t **, unsigned char *);
void fill_info_udp(raw_packet_t **, unsigned char *);
void fill_info_default(raw_packet_t **);
void fill_data_dump(raw_packet_t **, unsigned char *, int);
void print_raw(raw_packet_t *);
void *timer(void);
void import_pcapfile(char *, raw_packet_t **);

#endif
