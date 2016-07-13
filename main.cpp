#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

enum protoc{
    ipv4, ipv6, tcp
};

unsigned int protoc_[] = {0x0800, 0x0000, 0x06}; //not right

char * protoc_c[] = {"ipv4", "ipv6", "tcp"};

unsigned int offset = 0;

struct ether_addr
{
        unsigned char ether_addr_octet[6];
};

struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
};

struct ip_header
{
        unsigned char ip_header_len:4;
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        struct in_addr ip_srcaddr;
        struct in_addr ip_destaddr;
};

struct tcp_header
{
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int sequence;
        unsigned int acknowledge;
        unsigned char ns:1;
        unsigned char reserved_part1:3;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};

int set_ether(struct ether_header *eh, protoc p)
{
    unsigned short ether_type = ntohs(eh->ether_type);
    eh->ether_type = ether_type;
    if(ether_type != protoc_[p])
    {
        printf("not %s protocol", protoc_c[p]);
        return 0;
    }
    return 1;
}

void ether_print(struct ether_header * eh)
{
    printf("-----------------------------------\n");
    printf("ethernet header\n");
    printf("Src MAC Adress [%02x:%02x:%02x:%02x:%02x:%02x]\n", eh->ether_shost.ether_addr_octet[0], eh->ether_shost.ether_addr_octet[1], eh->ether_shost.ether_addr_octet[2],
            eh->ether_shost.ether_addr_octet[3], eh->ether_shost.ether_addr_octet[4], eh->ether_shost.ether_addr_octet[5]);
    printf("Dst MAC Adress [%02x:%02x:%02x:%02x:%02x:%02x]\n\n", eh->ether_dhost.ether_addr_octet[0], eh->ether_dhost.ether_addr_octet[1], eh->ether_dhost.ether_addr_octet[2],
            eh->ether_dhost.ether_addr_octet[3], eh->ether_dhost.ether_addr_octet[4], eh->ether_dhost.ether_addr_octet[5]);
    //printf("protocol : %s", protoc_c[eh->ether_type])
}

int set_ipv4(struct ip_header * ih, protoc p)
{
    if(ih->ip_version != 0x4)
    {
        printf("not ipv4\n");
        return 0;
    }

    if(protoc_[p]!=ih->ip_protocol)
    {
        printf("not %s\n", protoc_c[p]);
        return 0;
    }

    offset = ih->ip_header_len*4;
   // printf("ip header length = %d\n", offset);
    return 1;
}

void ip_print(struct ip_header * ih)
{
    printf("-----------------------------------\n");
    printf("IP header");
    printf("IPv%d\n", ih->ip_version);
    printf("Src IP Adress : %s\n", inet_ntoa(ih->ip_srcaddr));
    printf("Dst IP Adress : %s\n\n", inet_ntoa(ih->ip_destaddr));
}

void tcp_print(struct tcp_header * th)
{
    printf("-----------------------------------\n");
    printf("TCP header\n");
    printf("Src Port : %hu\n",ntohs(th->source_port));
    printf("Dst Port : %hu\n", ntohs(th->dest_port));
}


int main() //int main(int argc, char *argv[])
{
   //printf("started\n\n");
   pcap_t *handle;			/* Session handle */
   char *dev;			/* The device to sniff on */
   char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
   struct bpf_program fp;		/* The compiled filter */
   char filter_exp[] = "";	/* The filter expression */
   bpf_u_int32 mask;		/* Our netmask */
   bpf_u_int32 net;		/* Our IP */
   struct pcap_pkthdr header;	/* The header that pcap gives us */
   const u_char *packet;		/* The actual packet */

   //hyojun
   struct ether_header *eh;
   struct ip_header *ih;
   struct tcp_header * th;

   pcap_if_t *alldevs = NULL;

   char track[] = "취약점";
   char name[] = "신효준";
   printf("[bob5][%s]pcap_test[%s]\n\n", track, name);

   // find all network adapters
       if (pcap_findalldevs(&alldevs, errbuf) == -1) {
           printf("dev find failed\n");
           return -1;
       }
       if (alldevs == NULL) {
           printf("no devs found\n");
           //return -1;
       }
       // print them
       pcap_if_t *d; int i;
       for (d = alldevs, i = 0; d != NULL; d = d->next) {
           printf("%d-th dev: %s ", ++i, d->name);
           if (d->description)
               printf(" (%s)\n", d->description);
           else
               printf(" (No description available)\n");
       }

       int inum;

       printf("enter the interface number: ");
       scanf("%d", &inum);
       for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++); // jump to the i-th dev



   /* Define the device */
   /*

   dev = pcap_lookupdev(errbuf);
   if (dev == NULL) {
       fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
       return(2);
   }
   */
   dev = d->name;
   /* Find the properties for the device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
       net = 0;
       mask = 0;
   }
   /* Open the session in promiscuous mode */
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return(2);
   }

   //pcap open is before filtering. why?
   //ehternet base, sleep base, ... there are many types
   //so it can filter after opening.

   /* Compile and apply the filter */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return(2);
   }

   while(1)
   {
   /* Grab a packet */
   packet = pcap_next(handle, &header);
   /* Print its length */
   if(packet == NULL)
       continue;
   printf("===================================\n");
   printf("Jacked a packet with length of [%d]\n", header.len);
   /* And close the session */
   eh = (struct ether_header *)packet;
   ih = (struct ip_header *)(packet+14);

   if(set_ether(eh, ipv4) && set_ipv4(ih, tcp))
   {
       th = (struct tcp_header *)(packet+14+offset);
       ether_print(eh);
       ip_print(ih);
       tcp_print(th);
   }
   printf("\n===================================\n");
   printf("\n\n");

   }
   pcap_close(handle);
   return(0);
}


