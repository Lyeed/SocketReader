#include "includes/my_sniffer.h"

int sniffer(raw_packet_t **raw) {
  int saddr_size;
  int data_size;
  int num = 0;
  struct sockaddr saddr;
  unsigned char *buffer = (unsigned char *)malloc(65536);
  int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if (sock_raw < 0) {
    printf("need admin right\n");
    return -1;
  }

  while (num <= 10) {
    saddr_size = sizeof(saddr);
    data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
    if (data_size < 0)
      printf("recvfrom failed\n");
    fill_raw_packet(raw, buffer, num++);
  }
  close(sock_raw);
  return 0;
}

void fill_raw_packet(raw_packet_t **raw, unsigned char *buffer, int num) {
  raw_packet_t *packet = malloc(sizeof(raw_packet_t));
  raw_packet_t *tmp = (*raw);

  packet->num = num;
  packet->time = 0;
  fill_ethernet_header(&packet, buffer);
  fill_ip_header(&packet, buffer);
  fill_info_header(&packet, buffer);
  fill_data_dump(&packet, buffer);
  packet->next = NULL;
  if (tmp == NULL) {
    (*raw) = packet;
    return ;
  }
  while (tmp->next != NULL)
    tmp = tmp->next;
  packet->prev = tmp;
  tmp->next = packet;
}

void fill_ethernet_header(raw_packet_t **raw, unsigned char *buffer) {
  struct ethhdr *eth = (struct ethhdr *)buffer;
  ethernet_header_t *eh = malloc(sizeof(ethernet_header_t));

  eh->src_addr = malloc(sizeof(char) * 20);
  sprintf(eh->src_addr, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  eh->dest_addr = malloc(sizeof(char) * 20);
  sprintf(eh->dest_addr, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
  eh->proto = (unsigned short)eth->h_proto;  

  (*raw)->eth = eh;
}

void fill_ip_header(raw_packet_t **raw, unsigned char *buffer) {
  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  ip_header_t *ip = malloc(sizeof(ip_header_t));
  struct sockaddr_in source;
  struct sockaddr_in dest;

  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;

  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;
  
  ip->version = (unsigned int)iph->version;
  ip->header_len = (unsigned int)(iph->ihl)*4;
  ip->service_type = (unsigned int)(iph->tos);
  ip->total_len = ntohs(iph->tot_len);
  ip->id = ntohs(iph->id);
  ip->ttl = (unsigned int)iph->ttl;
  ip->proto = (unsigned int)iph->protocol;
  ip->checksum = ntohs(iph->check);
  ip->src_ip = strdup(inet_ntoa(source.sin_addr));
  ip->dest_ip = strdup(inet_ntoa(dest.sin_addr));

  (*raw)->ip = ip;
}

void fill_info_header(raw_packet_t **raw, unsigned char *buffer) {
  (*raw)->info = NULL;
}

void fill_data_dump(raw_packet_t **raw, unsigned char *buffer) {
  (*raw)->dump = NULL;
}


void *timer() {
  float timer = 0;

  while (1) {
    timer += 0.001;
    usleep(1);
    printf("%f\n", timer);
  }
}

void print_raw(raw_packet_t *raw) {
  while (raw != NULL) {
    printf("##############################\n");
    printf("PACKET NUMBER\n");
    printf("%d\n", raw->num);

    printf("\nPACKET ETHERNET HEADER\n");
    printf("%s\n", raw->eth->src_addr);
    printf("%s\n", raw->eth->dest_addr);
    printf("%u\n", raw->eth->proto);

    printf("\nPACKET IP HEADER\n");
    printf("%d\n", raw->ip->version);
    printf("%d\n", raw->ip->header_len);
    printf("%d\n", raw->ip->service_type);
    printf("%d\n", raw->ip->total_len);
    printf("%d\n", raw->ip->id);
    printf("%d\n", raw->ip->ttl);
    printf("%d\n", raw->ip->proto);
    printf("%d\n", raw->ip->checksum);
    printf("%s\n", raw->ip->src_ip);
    printf("%s\n", raw->ip->dest_ip);

    printf("\n");
    raw = raw->next;
    
  }
}

int main() {
  raw_packet_t *raw = NULL;

  sniffer(&raw);
  print_raw(raw);
  return 0;
}
