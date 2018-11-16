#include "sniffer.h"
#include "app.h"
#include "views.h"

raw_packet_t *getPacket(const guint num) {
  raw_packet_t *raw = app->raw;

  while (raw != NULL) {
    if (raw->num == num) {
      return raw;
    }
    raw = raw->next;
  }
  return NULL;
}

static void fill_info_arp(raw_packet_t *raw, unsigned char *buffer) {
  struct arphdr *arph = (struct arphdr *)(buffer + sizeof(struct ethhdr));
  info_packet_t *inf = malloc(sizeof(info_packet_t));
  arp_header_t *arp = malloc(sizeof(arp_header_t));

  arp->hrdw_f = arph->ar_hrd;
  arp->proto_f = arph->ar_pro;
  arp->hrdw_len = arph->ar_hln;
  arp->proto_len = arph->ar_pln;
  arp->op = arph->ar_op;

  inf->tcp = NULL;
  inf->udp = NULL;
  inf->icmp = NULL;
  inf->arp = arp;

  raw->info = inf;
  raw->proto = ARP;
}

static void fill_ip_header(raw_packet_t *raw, unsigned char *buffer) {
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

  raw->ip = ip;
}

static void fill_info_icmp(raw_packet_t *raw, unsigned char *buffer) {
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
  inf->arp = NULL;

  raw->info = inf;
  raw->proto = ICMP;
}

static void fill_info_tcp(raw_packet_t *raw, unsigned char *buffer) {
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
  inf->arp = NULL;

  raw->info = inf;
  raw->proto = (tcp->src_port == 80 || tcp->dest_port == 80) ? HTTP : TCP;
}

static void fill_info_udp(raw_packet_t *raw, unsigned char *buffer) {
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
  inf->arp = NULL;

  raw->info = inf;
  raw->proto = (udp->src_port == 53 || udp->dest_port == 53) ? DNS : UDP;
}

static void fill_info_default(raw_packet_t *raw) {
  info_packet_t *inf = malloc(sizeof(info_packet_t));

  inf->tcp = NULL;
  inf->udp = NULL;
  inf->icmp = NULL;
  inf->arp = NULL;

  raw->info = inf;
  raw->proto = Unknown;
}

static void fill_data_dump(raw_packet_t *raw, unsigned char *buffer, const ssize_t size) {
  data_dump_t *dump = malloc(sizeof(data_dump_t));
  int i = 0;
  char *hexa = malloc(sizeof(char) * (size_t)(size+1)*2);
  char *tmp = malloc(sizeof(char) * 5);
  char *ascii = malloc(sizeof(char) * (size_t)(size+1)*2);

  for (i = 0; i < size; i++) {
    sprintf(tmp, "%02X", (unsigned int)buffer[i]);
    i == 0 ? strcpy(hexa, tmp) : strcat(hexa, tmp);
  }
  free(tmp);

  for (i = 0; i < size; i++) {
    if (buffer[i] >= 32 && buffer[i] <= 128)
      ascii[i] = (char)buffer[i];
    else
      ascii[i] = '.';
  }
  ascii[i] = 0;

  dump->hexa = hexa;
  dump->ascii = ascii;
  raw->dump = dump;
}

static void fill_ethernet_header(raw_packet_t *raw, unsigned char *buffer) {
  struct ethhdr *eth = (struct ethhdr *)buffer;
  ethernet_header_t *eh = malloc(sizeof(ethernet_header_t));

  eh->src_addr = malloc(sizeof(char) * 20);
  sprintf(eh->src_addr, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  eh->dest_addr = malloc(sizeof(char) * 20);
  sprintf(eh->dest_addr, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
  eh->proto = ntohs(eth->h_proto);
  if (eh->proto == ETH_P_ARP)
    g_printerr("Warning: ARP packet not handled\n");
  raw->eth = eh;
}

static void fill_info_header(raw_packet_t *raw, unsigned char *buffer) {
  switch (raw->ip->proto) {

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

static int what_filter(void) {
  if (strncmp(app->filters, "host ", 5) == 0)
    return 1;
  else if (strncmp(app->filters, "port ", 5) == 0)
    return 2;
  else if (strncmp(app->filters, "proto ", 6) == 0)
    return 3;
  else
    return 0;
}

static int can_add(raw_packet_t *raw) {
  switch (what_filter()) {
  case 1:
    if (raw->ip != NULL)
      return (strcmp(raw->ip->dest_ip, (app->filters + 5)) != 0 && strcmp(raw->ip->src_ip, (app->filters + 5)) != 0) ? 0 : 1;
    break;
  case 2:
    if (raw->info->tcp != NULL) {
      return (atoi(app->filters + 5) != raw->info->tcp->src_port && atoi(app->filters + 5) != raw->info->tcp->dest_port) ? 0 : 1;
    } else if (raw->info->udp != NULL) {
      return (atoi(app->filters + 5) != raw->info->udp->src_port && atoi(app->filters + 5) != raw->info->udp->dest_port) ? 0 : 1;
    }
  case 3:
    return (strcmp(getProtocol(raw->proto), (app->filters + 6)) == 0) ? 1 : 0;
  default:
    break;
  }
  return 0;
}

static void fill_raw_packet(unsigned char *buffer, const ssize_t size, const int timerEnabled) {
  time_t recordTime;
  struct ethhdr *eth = (struct ethhdr *)buffer;
  if (ntohs(eth->h_proto) != ETH_P_IP && ntohs(eth->h_proto) != ETH_P_ARP) {
    return;
  }

  raw_packet_t *packet = malloc(sizeof(raw_packet_t));
  if (!packet) {
    g_printerr("packet malloc() failed\n");
    exit(-1);
  }
  raw_packet_t *tmp = app->raw;

  time(&recordTime);
  app->packetsCount += 1;
  packet->num = app->packetsCount;
  packet->time = (timerEnabled == 1) ? difftime(recordTime, app->start) : 0;
  packet->proto = Unknown;
  packet->length = (int)size;
  fill_ethernet_header(packet, buffer);

  if (ntohs(eth->h_proto) == ETH_P_ARP) {
    packet->ip = NULL;
    fill_info_arp(packet, buffer);
  }
  else {
    fill_ip_header(packet, buffer);
    fill_info_header(packet, buffer);
  }
  fill_data_dump(packet, buffer, size);
  if (can_add(packet) == 0) {
    app->packetsCount--;
    return;
  }


  fill_list(packet);
  packet->next = NULL;
  print_raw(packet);
  if (tmp == NULL) {
    app->raw = packet;
    return ;
  }
  while (tmp->next != NULL) {
    tmp = tmp->next;
  }
  packet->prev = tmp;
  tmp->next = packet;
}

void *sniffer(void *data) {
  struct sockaddr saddr;
  unsigned char *buffer = (unsigned char *)malloc(65536);
  ssize_t data_size;
  int saddr_size,
      sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if (sock_raw == -1) {
    perror("Socket");
    exit(-1);
  }

  g_print("sniffer()\n");
  app->packetsCount = 0;
  while (app->run) {
    saddr_size = sizeof(saddr);
    data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
    if (app->run) {
      if (data_size < 0) {
        g_printerr("recvfrom() failed\n");
      } else {
        fill_raw_packet(buffer, data_size, 1);
      }
    }
  }

  (void)data;
  close(sock_raw);
  return NULL;
}

char *getInfo(const raw_packet_t *raw) {
  char *info = malloc(sizeof(char) * 100);

  switch (raw->proto) {
  case 1:
  case 5:
    sprintf(info, "%d", raw->info->tcp->src_port);
    strcat(info, " -> ");
    sprintf(info + strlen(info), "%d", raw->info->tcp->dest_port);
    strcat(info, ", win= ");
    sprintf(info + strlen(info), "%d", raw->info->tcp->window);
    break;
  case 2:
  case 6:
    sprintf(info, "%d", raw->info->udp->src_port);
    strcat(info, " -> ");
    sprintf(info + strlen(info), "%d", raw->info->udp->dest_port);
    break;
  case 3:
    strcpy(info, "type= ");
    sprintf(info, "%d", raw->info->icmp->type);
    break;
  default:
    strcpy(info, raw->eth->src_addr);
    strcat(info, " -> ");
    strcat(info, raw->eth->dest_addr);
    break;
  }
  return info;
}

char *getHexa(const raw_packet_t *raw) {
  return strdup(raw->dump->hexa);
}

char *getAscii(const raw_packet_t *raw) {
  return strdup(raw->dump->ascii);
}

char *getAddrSource(const raw_packet_t *raw) {
  return raw->proto == ARP ? strdup(raw->eth->src_addr) : strdup(raw->ip->src_ip);
}

char *getAddrDest(const raw_packet_t *raw) {
  return raw->proto == ARP ? strdup(raw->eth->dest_addr) : strdup(raw->ip->dest_ip);
}

char *getProtocol(const int proto) {
  char *protocol = NULL;
  switch (proto) {
    case 0:
      protocol = strdup("Unknown");
      break;
    case 1:
      protocol = strdup("TCP");
      break;
    case 2:
      protocol = strdup("UDP");
      break;
    case 3:
      protocol = strdup("ICMP");
      break;
    case 4:
      protocol = strdup("ARP");
      break;
    case 5:
      protocol = strdup("HTTP");
      break;
    case 6:
      protocol = strdup("DNS");
      break;
  };
  return protocol;
}

void print_raw(const raw_packet_t *raw) {
  printf("##############################\n");
  printf("Number: %d\n", raw->num);
  printf("protocol: %s\n", getProtocol(raw->proto));
  printf("length: %d\n", raw->length);

  if (raw->ip != NULL) {
    printf("src addr: %s\n", raw->ip->src_ip);
    printf("dest addr: %s\n", raw->ip->dest_ip);
  }

  if (raw->info->tcp != NULL) {
    printf("src p: %d\n", raw->info->tcp->src_port);
    printf("dest p: %d\n", raw->info->tcp->dest_port);
    printf("window: %d\n", raw->info->tcp->window);
  }
  if (raw->info->udp != NULL) {
    printf("src p: %d\n", raw->info->udp->src_port);
    printf("dest p: %d\n", raw->info->udp->dest_port);
  }
  if (raw->info->icmp != NULL) {
    printf("code: %d\n", raw->info->icmp->code);
  }
  if (raw->info->arp != NULL) {
    printf("src eth: (%s)\n", raw->eth->src_addr);
    printf("dest eth: (%s)\n", raw->eth->dest_addr);
    printf("hdrw f: 0x%X\n", raw->info->arp->hrdw_f);
  }

  printf("%s\n", raw->dump->hexa);
  printf("%s\n", raw->dump->ascii);
  printf("##############################\n");
  printf("\n");
}

void export_pcapfile(const char *file) {
  g_print("export_pcapfile() %s\n", file);
  FILE *f = fopen(file, "w");
  raw_packet_t *raw = app->raw;
  int pow = 16777216;
  int size = 0;
  unsigned char ziz[4];
  unsigned char dup = 0;
  int i = 0;
  int tmp = 0;

  fprintf(f, "%c%c%c%c", 212, 195, 178, 161); //magic number
  fprintf(f, "%c%c%c%c", 2, 0, 4, 0); // version
  fprintf(f, "%c%c%c%c", 0, 0, 0, 0); //zone
  fprintf(f, "%c%c%c%c", 0, 0, 0, 0); //sig
  fprintf(f, "%c%c%c%c", 255, 255, 0, 0); //snap
  fprintf(f, "%c%c%c%c", 1, 0, 0, 0); //network

  while (raw != NULL) {
    size = (int)strlen(raw->dump->hexa)/2;

    fprintf(f, "%c%c%c%c", 0, 0, 0, 0); //sec
    fprintf(f, "%c%c%c%c", 0, 0, 0, 0); //usec

    while (pow > 0) {
      ziz[i++] = (unsigned char)(size / pow);
      size = size % pow;
      pow = pow / 256;
    }
    i = 0;
    pow = 16777216;
    size = (int)strlen(raw->dump->hexa);
    fprintf(f, "%c%c%c%c", ziz[3], ziz[2], ziz[1], ziz[0]);
    fprintf(f, "%c%c%c%c", ziz[3], ziz[2], ziz[1], ziz[0]);

    while (i < size) {
      tmp += (raw->dump->hexa[i] >= '0' && raw->dump->hexa[i] <= '9') ? (raw->dump->hexa[i] - '0') * 16 : (raw->dump->hexa[i] - 'A' + 10) * 16;
      tmp += (raw->dump->hexa[i+1] >= '0' && raw->dump->hexa[i+1] <= '9') ? (raw->dump->hexa[i+1] - '0') : (raw->dump->hexa[i+1] - 'A' + 10);
      dup = (unsigned char)tmp;
      fprintf(f, "%c", dup);
      i += 2;
      dup = 0;
      tmp = 0;
    }
    i = 0;
    raw = raw->next;
  }
}

void import_pcapfile(const char *file) {
  g_print("import_pcapfile() %s\n", file);
  app->raw = NULL;
  app->packetsCount = 0;
  FILE *f = fopen(file, "r");
  int c,
    i = 0,
    j = 0,
    stop = 0,
    pow = 1,
    size = 0;

  while (i < 24 && !feof(f)) { // GLOBAL HEADER
    c = fgetc(f);
    i++;
  }

  while (!feof(f)) {
    stop = i + 8;
    while (i < stop && !feof(f)) { // PACKET HEADER TIMER
      c = fgetc(f);
      i++;
    }

    stop = i + 4;
    while (i < stop && !feof(f)) { // PACKET HEADER SIZE
      c = fgetc(f);
      size += c * pow;
      if (i+1 != stop)
	pow = pow * 256;
      i++;
    }
    stop = i + 4;
    while (i < stop && !feof(f)) { // PACKET HEADER SIZE 2
      c = fgetc(f);
      i++;
    }

    stop = i + size;
    unsigned char *buffer = malloc((size_t)size);
    while (i < stop && !feof(f)) { // READ PACKET
      c = fgetc(f);
       buffer[j++] = (unsigned char)c;
       i++;
     }
    if (c != -1) {
      fill_raw_packet(buffer, size, 0);
    }
    buffer = NULL;
    j = 0;
    size = 0;
    pow = 1;
  }

  fclose(f);
}

char *getBigDetails(const raw_packet_t *raw) {
  char *str = malloc(sizeof(char) * 4096);

  switch(raw->proto) {
    case 1: //TCP
    case 5:
      strcpy(str, "ETHERNET HEADER\n");
      strcat(str, "Source: (");
      strcat(str, raw->eth->src_addr);
      strcat(str, ")\n");
      strcat(str, "Destination: (");
      strcat(str, raw->eth->dest_addr);
      strcat(str, ")\n");
      strcat(str, "Type: IPv4 (0x0800)\n");
      strcat(str, "\n");

      strcat(str, "IP HEADER\n");
      strcat(str, "Version: ");
      sprintf(str + strlen(str), "%d", raw->ip->version);
      strcat(str, "\n");
      strcat(str, "Header Length: ");
      sprintf(str + strlen(str), "%d", raw->ip->header_len);
      strcat(str, " bytes\n");
      strcat(str, "Services Field: ");
      sprintf(str + strlen(str), "0x%X", raw->ip->service_type);
      strcat(str, "\n");
      strcat(str, "Total Length: ");
      sprintf(str + strlen(str), "%d", raw->ip->total_len);
      strcat(str, "\n");
      strcat(str, "Identification: ");
      sprintf(str + strlen(str), "0x%X", raw->ip->id);
      strcat(str, "\n");
      strcat(str, "Time to live: ");
      sprintf(str + strlen(str), "%d", raw->ip->ttl);
      strcat(str, "\n");
      strcat(str, "Protocol: ");
      strcat(str, "TCP");
      strcat(str, "\n");
      strcat(str, "Header checksum: ");
      sprintf(str + strlen(str), "0x%X", raw->ip->checksum);
      strcat(str, "\n");
      strcat(str, "Source: ");
      strcat(str, raw->ip->src_ip);
      strcat(str, "\n");
      strcat(str, "Destination: ");
      strcat(str, raw->ip->dest_ip);
      strcat(str, "\n\n");

      strcat(str, "TCP HEADER\n");
      strcat(str, "Source Port: ");
      sprintf(str + strlen(str), "%d", raw->info->tcp->src_port);
      strcat(str, "\n");
      strcat(str, "Destination Port: ");
      sprintf(str + strlen(str), "%d", raw->info->tcp->dest_port);
      strcat(str, "\n");
      strcat(str, "Sequence number: ");
      sprintf(str + strlen(str), "%ld", raw->info->tcp->seq);
      strcat(str, "\n");
      strcat(str, "Window size value: ");
      sprintf(str + strlen(str), "%d", raw->info->tcp->window);
      strcat(str, "\n");
      strcat(str, "Checksum: ");
      sprintf(str + strlen(str), "0x%X", raw->info->tcp->checksum);
      strcat(str, "\n");
      strcat(str, "Urgent pointer: ");
      sprintf(str + strlen(str), "%d", raw->info->tcp->urg_ptr);
      strcat(str, "\n");
      break;
    case 2: //UDP
    case 6:
      	strcpy(str, "ETHERNET HEADER\n");
      	strcat(str, "Source: (");
      	strcat(str, raw->eth->src_addr);
      	strcat(str, ")\n");
      	strcat(str, "Destination: (");
      	strcat(str, raw->eth->dest_addr);
      	strcat(str, ")\n");
      	strcat(str, "Type: IPv4 (0x0800)\n");
      	strcat(str, "\n");

      	strcat(str, "IP HEADER\n");
      	strcat(str, "Version: ");
      	sprintf(str + strlen(str), "%d", raw->ip->version);
      	strcat(str, "\n");
      	strcat(str, "Header Length: ");
      	sprintf(str + strlen(str), "%d", raw->ip->header_len);
      	strcat(str, " bytes\n");
      	strcat(str, "Services Field: ");
      	sprintf(str + strlen(str), "0x%X", raw->ip->service_type);
      	strcat(str, "\n");
      	strcat(str, "Total Length: ");
      	sprintf(str + strlen(str), "%d", raw->ip->total_len);
      	strcat(str, "\n");
      	strcat(str, "Identification: ");
      	sprintf(str + strlen(str), "0x%X", raw->ip->id);
      	strcat(str, "\n");
      	strcat(str, "Time to live: ");
      	sprintf(str + strlen(str), "%d", raw->ip->ttl);
      	strcat(str, "\n");
      	strcat(str, "Protocol: ");
      	strcat(str, "TCP");
      	strcat(str, "\n");
      	strcat(str, "Header checksum: ");
      	sprintf(str + strlen(str), "0x%X", raw->ip->checksum);
      	strcat(str, "\n");
      	strcat(str, "Source: ");
      	strcat(str, raw->ip->src_ip);
      	strcat(str, "\n");
      	strcat(str, "Destination: ");
      	strcat(str, raw->ip->dest_ip);
      	strcat(str, "\n\n");

      	strcat(str, "UDP HEADER\n");
      	strcat(str, "Source Port: ");
      	sprintf(str + strlen(str), "%d", raw->info->udp->src_port);
      	strcat(str, "\n");
      	strcat(str, "Destination Port: ");
      	sprintf(str + strlen(str), "%d", raw->info->udp->dest_port);
      	strcat(str, "\n");
      	strcat(str, "Length: ");
      	sprintf(str + strlen(str), "%d", raw->info->udp->len);
      	strcat(str, "\n");
      	strcat(str, "Checksum: ");
      	sprintf(str + strlen(str), "0x%X", raw->info->udp->checksum);
      	strcat(str, "\n");
      	break;
      case 3: //ICMP
      	strcpy(str, "ETHERNET HEADER\n");
      	strcat(str, "Source: (");
      	strcat(str, raw->eth->src_addr);
      	strcat(str, ")\n");
      	strcat(str, "Destination: (");
      	strcat(str, raw->eth->dest_addr);
      	strcat(str, ")\n");
      	strcat(str, "Type: IPv4 (0x0800)\n");
      	strcat(str, "\n");

      	strcat(str, "IP HEADER\n");
      	strcat(str, "Version: ");
      	sprintf(str + strlen(str), "%d", raw->ip->version);
      	strcat(str, "\n");
      	strcat(str, "Header Length: ");
      	sprintf(str + strlen(str), "%d", raw->ip->header_len);
      	strcat(str, " bytes\n");
      	strcat(str, "Services Field: ");
      	sprintf(str + strlen(str), "0x%X", raw->ip->service_type);
      	strcat(str, "\n");
      	strcat(str, "Total Length: ");
      	sprintf(str + strlen(str), "%d", raw->ip->total_len);
      	strcat(str, "\n");
      	strcat(str, "Identification: ");
      	sprintf(str + strlen(str), "0x%X", raw->ip->id);
      	strcat(str, "\n");
      	strcat(str, "Time to live: ");
      	sprintf(str + strlen(str), "%d", raw->ip->ttl);
      	strcat(str, "\n");
      	strcat(str, "Protocol: ");
      	strcat(str, "TCP");
      	strcat(str, "\n");
      	strcat(str, "Header checksum: ");
      	sprintf(str + strlen(str), "0x%X", raw->ip->checksum);
      	strcat(str, "\n");
      	strcat(str, "Source: ");
      	strcat(str, raw->ip->src_ip);
      	strcat(str, "\n");
      	strcat(str, "Destination: ");
      	strcat(str, raw->ip->dest_ip);
      	strcat(str, "\n\n");

      	strcat(str, "ICMP HEADER\n");
      	strcat(str, "Type: ");
      	sprintf(str + strlen(str), "%d", raw->info->icmp->type);
      	strcat(str, "\n");
      	strcat(str, "Code: ");
      	sprintf(str + strlen(str), "%d", raw->info->icmp->code);
      	strcat(str, "\n");
      	strcat(str, "Checksum: ");
      	sprintf(str + strlen(str), "0x%X", raw->info->icmp->checksum);
      	strcat(str, "\n");
      	break;

      case 4: //ARP
      	strcpy(str, "ETHERNET HEADER\n");
      	strcat(str, "Source: (");
      	strcat(str, raw->eth->src_addr);
      	strcat(str, ")\n");
      	strcat(str, "Destination: (");
      	strcat(str, raw->eth->dest_addr);
      	strcat(str, ")\n");
      	strcat(str, "Type: ARP (0x0806)\n");
      	strcat(str, "\n");

      	strcat(str, "ARP HEADER\n");
      	strcat(str, "Hardware type: ");
      	sprintf(str + strlen(str), "0x%X", raw->info->arp->hrdw_f);
      	strcat(str, "\n");
      	strcat(str, "Protocol type: ");
      	sprintf(str + strlen(str), "0x%X", raw->info->arp->proto_f);
      	strcat(str, "\n");
      	strcat(str, "Hardware size: ");
      	sprintf(str + strlen(str), "%d", raw->info->arp->hrdw_len);
      	strcat(str, "\n");
      	strcat(str, "Protocol size: ");
      	sprintf(str + strlen(str), "%d", raw->info->arp->proto_len);
      	strcat(str, "\n");
      	break;

      case 0: //Unknonw
        strcpy(str, "UNKNOWN PACKET\n");
        strcat(str, "Source: (");
        strcat(str, raw->eth->src_addr);
        strcat(str, ")\n");
        strcat(str, "Destination: (");
        strcat(str, raw->eth->dest_addr);
        strcat(str, ")\n");
        strcat(str, "Length: ");
        sprintf(str + strlen(str), "%d", raw->length);
        strcat(str, "\n");
  }
  return str;
}
