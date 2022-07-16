
/* Easy Sniffer
 *
 * Author: slowjuggler <atalubr@gmail.com>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. 
 *
 * As a special exception, the copyright holder of this utility give you
 * permission to link this utility with independent modules to produce an
 * executable, regardless of the license terms of these independent modules,
 * and to copy and distribute the resulting executable under terms of your choice.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>

#define BUF_MAX 65536

struct sockaddr_in saddr, daddr, addr;
struct tcphdr *tcph;
struct udphdr *udph;
struct ethhdr *eth; 
struct iphdr *iph;
struct tm *tptr;

uint64_t total = 0;
FILE *fp = NULL;
time_t present;
int rs = 0;

void rec_loop(void (*handle_frame)(unsigned char*, unsigned int));
void (*handle_frame)(unsigned char*, unsigned int) = NULL;
void data_print(unsigned char*, unsigned int);
void print_up(unsigned char*, unsigned int);
void log_up(unsigned char*, unsigned int);
void sigkill(int);
void sigchld(int);


/*Handle finished child process
void sigchld(int signal) { 
	
	while (waitpid(-1, NULL, WNOHANG) > 0);
}
*/

/*Handle kill signal*/
void sigkill(int signal) {	
	close(rs);
	fclose(fp);
	exit(1);
}
	
/*Data processing */
void rec_loop(void (*handle_frame)(unsigned char*, unsigned int)) {
	unsigned char buf[BUF_MAX];
	socklen_t addrlen = sizeof(addr);
	memset(buf, 0x00, BUF_MAX);	
	while (1) {									
		ssize_t rbytes = recvfrom(rs, buf, BUF_MAX, 0, (struct sockaddr*)&addr, &addrlen);
		if (rbytes == -1) {
			fprintf(stderr, "frame recieve error\n");
			exit(1);
		} else if (rbytes == sizeof(buf))  {
			 fprintf(stderr, "frame is too large for buffer");
		} else {
			handle_frame(buf, rbytes);
		}
	}
}

/*Data segment processing*/
void data_print(unsigned char* data, unsigned int size) {
	int offset = 0;
	int tot_lines = size/16;
	if (tot_lines*16 < size) {
		tot_lines++;
	}
	printf("\n |* Data buffer in HEX\n\n");	
	for (size_t i=0; i<tot_lines; i++) {
		printf("%04X ", offset);
		for (size_t j=0; j<16; j++) {
			printf("%02X ", data[offset+j]);
		}
		offset+=16;
		printf("\n");
	}
	printf("\n |* Data buffer in ASCII\n\n");
	for (size_t i=0; i<size; i++) {
		printf("%c", data[i]);
	}
	printf("\n");
}
	
/*Headers handle to print*/	
void print_up(unsigned char* buffer, unsigned int size) {
	eth = (struct ethhdr*)buffer;
	iph = (struct iphdr*)(buffer+ETH_HLEN);
	memset(&saddr, 0x00, sizeof(saddr));
	memset(&daddr, 0x00, sizeof(daddr));
	saddr.sin_addr.s_addr = iph->saddr;
	daddr.sin_addr.s_addr = iph->daddr;
	printf("\n |* Source MAC %.2X:%.2X:%.2X:%.2X:%.2X:%.2X >--> ", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("Destination MAC %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf(" |* Protocol 0x%.4X\n\n", htons((__be16)eth->h_proto));
	if (htons(eth->h_proto) == 0x0800) {
		printf(" |*		IP Header\n");
		printf(" |* IP Version           : %d\n", (unsigned int)iph->version);
		printf(" |* IP Header Length     : %d Bytes\n", ((unsigned int)(iph->ihl))*4);
		printf(" |* Type Of Service      : %d\n", (unsigned int)iph->tos);
		printf(" |* IP Total Length      : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
		printf(" |* Identification       : %d\n", ntohs(iph->id));
		printf(" |* TTL                  : %d\n", (unsigned int)iph->ttl);
		printf(" |* Protocol             : %d\n", (unsigned int)iph->protocol);
		printf(" |* Checksum             : %d\n", ntohs(iph->check));
		printf(" |* Source IP            : %s\n", inet_ntoa(saddr.sin_addr));
		printf(" |* Destination IP       : %s\n\n", inet_ntoa(daddr.sin_addr));
	}	
	if (iph->protocol == IPPROTO_TCP) {
		tcph = (struct tcphdr*)(buffer+ETH_HLEN+(iph->ihl)*4);
		printf(" |*		TCP header\n");
		printf(" |* Source %s : %d\t>-->\t", inet_ntoa(saddr.sin_addr), ntohs(tcph->source));
		printf("Destination %s : %d\n", inet_ntoa(daddr.sin_addr), ntohs(tcph->dest));
		printf(" |* Sequence Number      : %u\n", ntohl(tcph->seq));
		printf(" |* Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
		printf(" |* Header Length        : %d Bytes\n", ((unsigned int)(tcph->doff)) * 4);
		printf(" |* Urgent Flag          : %d\n", (unsigned int)tcph->urg);
		printf(" |* Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
		printf(" |* Push Flag            : %d\n", (unsigned int)tcph->psh);
		printf(" |* Reset Flag           : %d\n", (unsigned int)tcph->rst);
		printf(" |* Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
		printf(" |* Finish Flag          : %d\n", (unsigned int)tcph->fin);
		printf(" |* Window               : %d\n", ntohs(tcph->window));
		printf(" |* Checksum             : %d\n", ntohs(tcph->check));
		printf(" |* Urgent Pointer       : %d\n\n", tcph->urg_ptr);
		if (size - (ETH_HLEN + (iph->ihl)*4 + (tcph->doff)*4)) {
			data_print(buffer+ETH_HLEN+(iph->ihl)*4+(tcph->doff)*4, size-(ETH_HLEN+(iph->ihl)*4+(tcph->doff)*4));
		}				
	}
	if (iph->protocol == IPPROTO_UDP) {
		udph = (struct udphdr*)(buffer+ETH_HLEN+(iph->ihl)*4);
		printf(" |*		UDP Header\n");
		printf(" |* Source Port          : %d\n", ntohs(udph->source));
		printf(" |* Destination Port     : %d\n", ntohs(udph->dest));
		printf(" |* UDP Length           : %d\n", ntohs(udph->len));
		printf(" |* UDP Checksum         : %d\n\n", ntohs(udph->check));
		if (size - (ETH_HLEN + (iph->ihl)*4 + sizeof(udph))) {
			data_print(buffer+ETH_HLEN+(iph->ihl)*4+sizeof(udph), size-(ETH_HLEN+(iph->ihl)*4+sizeof(udph)));
		}
	}
	total++;
	printf("****************************** Packet# %ld recieved **********************************\n", total);	
}

/*Headers handle to log mode*/
void log_up(unsigned char* buffer, unsigned int size) {
	eth = (struct ethhdr*)buffer;
	iph = (struct iphdr*)(buffer+ETH_HLEN);
	memset(&saddr, 0x00, sizeof(saddr));
	memset(&daddr, 0x00, sizeof(daddr));
	saddr.sin_addr.s_addr = iph->saddr;
	daddr.sin_addr.s_addr = iph->daddr;
	present = time(NULL);
	tptr = localtime(&present);	
	fprintf(fp, "%d/%d/%d:%d:%d  ", 1+tptr->tm_mon, tptr->tm_mday, tptr->tm_hour, tptr->tm_min, tptr->tm_sec);
	fprintf(fp, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X >-> ", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(fp, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	fprintf(fp, "Proto 0x%.4X\n", htons((__be16)eth->h_proto));			
	if (htons(eth->h_proto) == 0x0800) {
		fprintf(fp, "\t\t\t  SIP %s >-> ", inet_ntoa(saddr.sin_addr));
		fprintf(fp, "DIP %s ", inet_ntoa(daddr.sin_addr));					
		fprintf(fp, "IPVer:%d ", (unsigned int)iph->version);
		fprintf(fp, "IPLen:%d bytes ", ntohs(iph->tot_len));
		fprintf(fp, "TTL:%d ", (unsigned int)iph->ttl);
		fprintf(fp, "Proto:%d ", (unsigned int)iph->protocol);
		fprintf(fp, "Checksum:%d\n", ntohs(iph->check));		
	}	
	if (iph->protocol == IPPROTO_TCP) {
		tcph = (struct tcphdr*)(buffer+ETH_HLEN+(iph->ihl)*4);
		fprintf(fp, "\t\t\t  SeqNum:%u ", ntohl(tcph->seq));
		fprintf(fp, "AckNum:%u ", ntohl(tcph->ack_seq));
		fprintf(fp, "Urg:%d ", (unsigned int)tcph->urg);
		fprintf(fp, "AckF:%d ", (unsigned int)tcph->ack);
		fprintf(fp, "Psh:%d ", (unsigned int)tcph->psh);
		fprintf(fp, "Rst:%d ", (unsigned int)tcph->rst);
		fprintf(fp, "Syn:%d ", (unsigned int)tcph->syn);
		fprintf(fp, "Fin:%d ", (unsigned int)tcph->fin);
		fprintf(fp, "Win:%d ", ntohs(tcph->window));
		fprintf(fp, "Check:%d\n", ntohs(tcph->check));
	}
	if (iph->protocol == IPPROTO_UDP) {
		udph = (struct udphdr*)(buffer+ETH_HLEN+(iph->ihl)*4);
		fprintf(fp, "\t\t\t  SPort:%d ", ntohs(udph->source));
		fprintf(fp, "DPort:%d ", ntohs(udph->dest));
		fprintf(fp, "UDPLen:%d ", ntohs(udph->len));
		fprintf(fp, "UDPCheck:%d\n", ntohs(udph->check));
	}
}

int main(int argc, char *argv[]) {
	struct ifreq ifr;
	struct sockaddr_ll sll;	
	char *ifname = NULL;
	char *file = NULL;
	int opt;
	while ((opt = getopt(argc, argv, "i:f:")) != -1) {
		switch(opt) {
			case 'f':
				file = optarg;
				break;
			case 'i':
				ifname = optarg;
				break;
		}
	}
	if (!ifname) {
		printf("syntax error!\nplease try again in format:\n%s -i [interface name] -f [log filename]\n", argv[0]);
		exit(1);
	}
	/*AF_PACKET socket creating*/
	rs = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (rs < 0) {
		perror("Socket creating error\n");
	}
	/*Bind to device by name*/	
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	memset(&sll, 0x00, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	/*Bind to device by index*/
	if (bind(rs, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
			perror("bind down");
			return -1;
	}		
	signal(SIGTERM, sigkill);
//	signal(SIGCHLD, sigchld);
	printf ("Starting on %s\n", ifname);
	if (file) {
		fp = fopen(file, "w+");		
		/*Process daemonizing*/
		if (fork() == 0) {		
			rec_loop(&log_up);
			close(rs);
			fclose(fp);
			exit(1);
		}	
	} else { 
		rec_loop(&print_up);	
	}
return 0;
}
