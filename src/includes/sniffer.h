#ifndef my_sniffer_h
#define my_sniffer_h

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
  int src_port;
  int dest_port;
  int seq_nb;
  int ack_seq;
  int len;
  int urg;
  int ack;
  int push;
  int reset;
  int sync;
  int fin;
  int window;
  int checksum;
  int urg_ptr;
} tcp_header_t;

//DNS port=53 == UDP
typedef struct udp_header_s {
  int src_port;
  int dest_port;
  int len;
  int checksum;
} udp_header_t;

typedef struct icmp_header_s {
  int type;
  int code;
  int checksum;
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
  ethernet_header_t *eth;
  ip_header_t *ip;
  info_packet_t *info;
  data_dump_t *dump;
  struct raw_packet_s *next;
  struct raw_packet_s *prev;
} raw_packet_t;

int sniffer(raw_packet_t **);
void fill_raw_packet(raw_packet_t **raw, unsigned char *, int);
void fill_ethernet_header(raw_packet_t **, unsigned char *);
void fill_ip_header(raw_packet_t **, unsigned char *);
void fill_info_header(raw_packet_t **, unsigned char *);
void fill_data_dump(raw_packet_t **, unsigned char *);
void print_raw(raw_packet_t *);
void *timer();

#endif
