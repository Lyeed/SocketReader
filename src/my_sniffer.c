#include "my_sniffer.h"

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

  while (num != 10) {
    saddr_size = sizeof(saddr);
    data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
    if (data_size < 0)
      printf("recvfrom failed\n");
    fill_raw_packet(raw, buffer, data_size, num++);
  }
  close(sock_raw);
  return 0;
}

void fill_raw_packet(raw_packet_t **raw, unsigned char *buffer, int size, int num) {
  raw_packet_t *packet = malloc(sizeof(raw_packet_t));
  raw_packet_t *tmp = (*raw);

  packet->num = num;
  packet->time = 0;
  packet->proto = Unknown;
  fill_ethernet_header(&packet, buffer);
  fill_ip_header(&packet, buffer);
  fill_info_header(&packet, buffer);
  fill_data_dump(&packet, buffer, size);
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
  eh->proto = ntohs(eth->h_proto);
  if (eh->proto == ETH_P_ARP)
    printf("ARP DETECTED !! :oooo\n");
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
  ip->header_len = (unsigned int)(iph->ihl*4);
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
  switch ((*raw)->ip->proto) {

  case 1: //ICMP
    fill_info_icmp(raw, buffer);
    break;

  case 6: //TCP HTTP
    fill_info_tcp(raw, buffer);
    break;
    
  case 17: //UDP DNS
    fill_info_udp(raw, buffer);
    break;

  default:
    fill_info_default(raw);
    break;
  }
}

void fill_info_icmp(raw_packet_t **raw, unsigned char *buffer) {
  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  struct icmphdr *icmph = (struct icmphdr *)(buffer + (iph->ihl)*4 + sizeof(struct ethhdr));
  info_packet_t *inf = malloc(sizeof(info_packet_t));
  icmp_header_t *icmp = malloc(sizeof(icmp_header_t));

  icmp->type = (unsigned int)(icmph->type);
  icmp->code = (unsigned int)(icmph->code);
  icmp->checksum = ntohs(icmph->checksum);

  inf->tcp = NULL;
  inf->udp = NULL;
  inf->icmp = icmp;
  
  (*raw)->info = inf;
  (*raw)->proto = ICMP;
}

void fill_info_tcp(raw_packet_t **raw, unsigned char *buffer) {
  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  struct tcphdr *tcph = (struct tcphdr *)(buffer + (iph->ihl)*4 + sizeof(struct ethhdr));
  info_packet_t *inf = malloc(sizeof(info_packet_t));
  tcp_header_t *tcp = malloc(sizeof(tcp_header_t));

  tcp->src_port = ntohs(tcph->source);
  tcp->dest_port = ntohs(tcph->dest);
  tcp->seq = ntohl(tcph->seq);
  tcp->ack_seq = ntohl(tcph->ack_seq);
  tcp->len = (unsigned int)(tcph->doff*4);
  tcp->urg = (unsigned int)(tcph->urg);
  tcp->ack = (unsigned int)(tcph->ack);
  tcp->push = (unsigned int)(tcph->psh);
  tcp->reset = (unsigned int)(tcph->rst);
  tcp->sync = (unsigned int)(tcph->syn);
  tcp->fin = (unsigned int)(tcph->fin);
  tcp->window = ntohs(tcph->window);
  tcp->checksum = ntohs(tcph->check);
  tcp->urg_ptr = tcph->urg_ptr;

  inf->tcp = tcp;
  inf->udp = NULL;
  inf->icmp = NULL;

  (*raw)->info = inf;
  
  (*raw)->proto = (tcp->src_port == 80 || tcp->dest_port == 80) ? HTTP : TCP;
}

void fill_info_udp(raw_packet_t **raw, unsigned char *buffer) {
  struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  struct udphdr *udph = (struct udphdr *)(buffer + (iph->ihl)*4 + sizeof(struct ethhdr));
  info_packet_t *inf = malloc(sizeof(info_packet_t));
  udp_header_t *udp = malloc(sizeof(udp_header_t));

  udp->src_port = ntohs(udph->source);
  udp->dest_port = ntohs(udph->dest);
  udp->len = ntohs(udph->len);
  udp->checksum = ntohs(udph->check);

  inf->tcp = NULL;
  inf->udp = udp;
  inf->icmp = NULL;

  (*raw)->info = inf;
  (*raw)->proto = (udp->src_port == 53 || udp->dest_port == 53) ? DNS : UDP;
}

void fill_info_default(raw_packet_t **raw) {
  info_packet_t *inf = malloc(sizeof(info_packet_t));

  inf->tcp = NULL;
  inf->udp = NULL;
  inf->icmp = NULL;

  (*raw)->info = inf;
  (*raw)->proto = Unknown;
}

void fill_data_dump(raw_packet_t **raw, unsigned char *buffer, int size) {
  data_dump_t *dump = malloc(sizeof(data_dump_t));
  int i = 0;
  char *hexa = malloc(sizeof(char) * (size+1)*2);
  char *tmp = malloc(sizeof(char) * 5);
  char *ascii = malloc(sizeof(char) * (size+1)*2);

  for (i = 0; i < size; i++) {
    sprintf(tmp, "%02X", (unsigned int)buffer[i]);
    strcat(hexa, tmp);
  }
  
  for (i = 0; i < size; i++) {    
    if (buffer[i] >= 32 && buffer[i] <= 128)
      ascii[i] = buffer[i];
    else
      ascii[i] = '.';
  }
  ascii[i] = 0;

  dump->hexa = hexa;
  dump->ascii = ascii;
  (*raw)->dump = dump;
}


void *timer() {
  float timer = 0;

  while (1) {
    timer += 0.001;
    usleep(1);
    printf("%f\n", timer);
  }
}

void print_protocol(int proto) {
  printf("protocol: ");
  switch (proto) {
  case 0:
    printf("Unknown\n");
    break;
  case 1:
    printf("TCP\n");
    break;
  case 2:
    printf("UDP\n");
    break;
  case 3:
    printf("ICMP\n");
    break;
  case 4:
    printf("ARP\n");
    break;
  case 5:
    printf("HTTP\n");
    break;
  case 6:
    printf("DNS\n");
    break;
  };
}

void print_raw(raw_packet_t *raw) {
  while (raw != NULL) {
    printf("##############################\n");
    printf("Number: %d\n", raw->num);
    print_protocol(raw->proto);
    
    /*printf("\nPACKET ETHERNET HEADER\n");
    printf("%s\n", raw->eth->src_addr);
    printf("%s\n", raw->eth->dest_addr);
    printf("%u\n", raw->eth->proto);*/

    /*printf("%d\n", raw->ip->version);
    printf("%d\n", raw->ip->header_len);
    printf("%d\n", raw->ip->service_type);
    printf("%d\n", raw->ip->total_len);
    printf("%d\n", raw->ip->id);
    printf("%d\n", raw->ip->ttl);
    printf("%d\n", raw->ip->proto);
    printf("%d\n", raw->ip->checksum);*/
    printf("src addr: %s\n", raw->ip->src_ip);
    printf("dest addr: %s\n", raw->ip->dest_ip);

    if (raw->info->tcp != NULL) {
      printf("%d\n", raw->info->tcp->src_port);
      printf("%d\n", raw->info->tcp->dest_port);
      printf("%d\n", raw->info->tcp->len);
      printf("%d\n", raw->info->tcp->window);
    }
    if (raw->info->udp != NULL) {
      printf("%d\n", raw->info->udp->src_port);
      printf("%d\n", raw->info->udp->dest_port);
      printf("%d\n", raw->info->udp->len);      
    }
    if (raw->info->icmp != NULL) {
      printf("%d\n", raw->info->icmp->code);
    }

    printf("%s\n", raw->dump->hexa);
    printf("%s\n", raw->dump->ascii);    
    printf("##############################\n");
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
