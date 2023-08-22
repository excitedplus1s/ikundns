#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>

#include <linux/filter.h>

#include <pthread.h>

#define BIND_SOCKET 12345

struct psd_tcp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
};

struct tcphdr_opt {
	struct tcphdr tcp;
	int mss;
};


struct psd_tcp_opt {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short tcp_len;
	struct tcphdr_opt tcp;
};

struct dns_answer_hdr_t {
	unsigned short tid;
	unsigned short flags;
	unsigned short questioncount;
	unsigned short answercount;
	unsigned short nsquerycount;
	unsigned short addtionalcount;
};

struct dns_answer_query_t {
	unsigned short type;
	unsigned short class_type;
};

void cap_fix_bug(int cap_socket)
{
	// zero_bpf trick
	struct sock_filter zero_filter = BPF_STMT(BPF_RET | BPF_K, 0);
	struct sock_fprog zero_filter_bpf = {
			.len = 1,
			.filter = &zero_filter,
	};
	if(setsockopt(cap_socket, SOL_SOCKET, SO_ATTACH_FILTER, &zero_filter_bpf, sizeof(zero_filter_bpf)) < 0)
	{
		perror("clean bpf failed");
		close(cap_socket);
		exit(1);
	}
	char drain[1];
	while (1) {
		int bytes = recv(cap_socket, drain, sizeof(drain), MSG_DONTWAIT);
		if ( bytes == -1 ){
			break;
		}
	}
}

unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}


unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
	struct psd_tcp buf;
	u_short ans;

	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_TCP;
	buf.tcp_len = htons(len);
	u_char cksum_data[4096] = {0};
	memcpy(cksum_data, &buf, sizeof(buf));
	u_char *payload_data = cksum_data + sizeof(buf);
	memcpy(payload_data, addr, len);
	ans = in_cksum((unsigned short *)cksum_data, sizeof(buf) + len);
	return ans;
}

void construct_dns_query_packet_and_send(char *buff, int len, const char *qname)
{
	u_char send_buff_segment1[4096] = {0};
	u_char send_buff_segment2[4096] = {0};
	u_char send_buff_fake[4096] = {0};
	u_char *ip_buff = buff + sizeof(struct ether_header);
	unsigned int send_len_segment1 = len - sizeof(struct ether_header);
	unsigned int send_len_segment2 = send_len_segment1;
	memcpy(send_buff_segment1, ip_buff, send_len_segment1);
	memcpy(send_buff_segment2, ip_buff, send_len_segment2);
	
	u_char pre_payload[] = {
		0x61,0x79,0x01,0x20,0x00,0x01,0x00,0x00,
		0x00,0x00,0x00,0x01
	};
	
	u_char suff_payload[] = {
		0x00,0x01,0x00,0x01,0x00,0x00,0x29,0x10,
		0x00,0x00,0x00,0x00,0x00,0x00,0x0c,0x00,
		0x0a,0x00,0x08,0x6a,0x6e,0x74,0x6d,0x6a,
		0x6e,0x74,0x6d
	};
	
	u_char fake_options[] = {
		0x13,0x12,0x69,0x6b,0x75,0x6e,0x69,0x6b,
		0x75,0x6e,0x69,0x6b,0x75,0x6e,0x69,0x6b,
		0x63,0x78,0x6b,0x00
	};
	
	u_char fake_payload[] = {
		0x69,0x6b,0x75,0x6e,0x69,0x6b,0x75,0x6e,
		0x69,0x6b,0x75,0x6e,0x69,0x6b,0x75,0x6e,
		0x69,0x6b,0x75,0x6e,0x69,0x6b,0x75,0x6e,
		0x69,0x6b,0x75,0x6e,0x69
	};
	
	int qname_packet_len = strlen(qname) + 2;
	u_short dns_len = qname_packet_len + sizeof(pre_payload) + sizeof(suff_payload);
	u_short net_dns_len = htons(dns_len);
	
	u_char *payload_segment1 = send_buff_segment1 + send_len_segment1;
	memcpy(payload_segment1, &net_dns_len, sizeof(net_dns_len));
	send_len_segment1 += sizeof(net_dns_len);
	
	u_char *payload__segment1_ = send_buff_segment1 + send_len_segment1;
	memcpy(payload__segment1_, &pre_payload, sizeof(pre_payload));
	send_len_segment1 += sizeof(pre_payload);
	
	const char delim[2]=".";
	char *qname_dup=strdup(qname);
	char *qname_packet_ = (char*)malloc(qname_packet_len);
	char *qname_packet = qname_packet_;
	char* token=strtok(qname_dup, delim);
	while(token != NULL){
		size_t len = strlen(token);
		*qname_packet = len;
		qname_packet++;
		strncpy(qname_packet, token, len + 1);
		qname_packet += len;
		token = strtok(NULL, delim);
	}
	free(qname_dup);
	
	payload__segment1_ = send_buff_segment1 + send_len_segment1;
	memcpy(payload__segment1_, qname_packet_, qname_packet_len/2);
	send_len_segment1 += qname_packet_len/2;
	u_char *payload_segment2 = send_buff_segment2 + send_len_segment2;
	u_char *payload_segment2_ = payload_segment2;
	memcpy(payload_segment2_, qname_packet_ + qname_packet_len/2, qname_packet_len - qname_packet_len/2);
	send_len_segment2 += (qname_packet_len - qname_packet_len/2);
	free(qname_packet_);
	
	payload_segment2_ = send_buff_segment2 + send_len_segment2;
	memcpy(payload_segment2_, &suff_payload, sizeof(suff_payload));
	send_len_segment2 += sizeof(suff_payload);
	
	
	struct ip ip_header;
	memcpy(&ip_header, send_buff_segment1, sizeof(struct ip));
	ip_header.ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + (dns_len + sizeof(dns_len));
	ip_header.ip_id = htons(ntohs(ip_header.ip_id) + 1);
	ip_header.ip_sum = 0x00;
	ip_header.ip_sum = in_cksum((unsigned short *)&ip_header, sizeof(struct ip));
	
	memcpy(send_buff_segment1, &ip_header, sizeof(struct ip));
	
	u_char *tcp_buff_segment1 = send_buff_segment1 + sizeof(struct ip);
	struct tcphdr tcp_header_segment1;
	int tcp_header_len_segment1 = send_len_segment1 - sizeof(struct ip);
	memcpy(&tcp_header_segment1, tcp_buff_segment1, sizeof(struct tcphdr));
	tcp_header_segment1.th_flags = TH_ACK | TH_PUSH;
	tcp_header_segment1.th_sum = 0;
	memcpy(tcp_buff_segment1, &tcp_header_segment1, sizeof(struct tcphdr));
	tcp_header_segment1.th_sum = in_cksum_tcp(ip_header.ip_src.s_addr, ip_header.ip_dst.s_addr, (unsigned short *)tcp_buff_segment1, tcp_header_len_segment1);
	memcpy(tcp_buff_segment1, &tcp_header_segment1, sizeof(struct tcphdr));
	
	
	memcpy(send_buff_segment2, &ip_header, sizeof(struct ip));
	u_char *tcp_buff_segment2 = send_buff_segment2 + sizeof(struct ip);
	struct tcphdr tcp_header_segment2;
	int tcp_header_len_segment2 = send_len_segment2 - sizeof(struct ip);
	memcpy(&tcp_header_segment2, tcp_buff_segment2, sizeof(struct tcphdr));
	tcp_header_segment2.th_flags = TH_ACK | TH_PUSH;
	tcp_header_segment2.th_seq = htonl(ntohl(tcp_header_segment1.th_seq) + tcp_header_len_segment1 - tcp_header_segment1.th_off * 4); 
	tcp_header_segment2.th_sum = 0;
	memcpy(tcp_buff_segment2, &tcp_header_segment2, sizeof(struct tcphdr));
	tcp_header_segment2.th_sum = in_cksum_tcp(ip_header.ip_src.s_addr, ip_header.ip_dst.s_addr, (unsigned short *)tcp_buff_segment2, tcp_header_len_segment2);
	memcpy(tcp_buff_segment2, &tcp_header_segment2, sizeof(struct tcphdr));
	
	memcpy(send_buff_fake, &ip_header, sizeof(struct ip));
	u_char *tcp_buff_fake = send_buff_fake + sizeof(struct ip);
	memcpy(tcp_buff_fake, &tcp_header_segment1, sizeof(struct tcphdr));
	struct tcphdr tcp_header_fake;
	memcpy(&tcp_header_fake, tcp_buff_fake, sizeof(struct tcphdr));
	tcp_header_fake.th_off = 10;
	tcp_header_fake.th_sum = 0;
	memcpy(tcp_buff_fake, &tcp_header_fake, sizeof(struct tcphdr));
	u_char *options_buff_fake = tcp_buff_fake + sizeof(struct tcphdr);
	memcpy(options_buff_fake, fake_options, sizeof(fake_options));
	u_char *payload = tcp_buff_fake + 40;
	memcpy(payload, fake_payload, sizeof(fake_payload));
	unsigned int tcp_fake_len = 40 + sizeof(fake_payload);
	tcp_header_fake.th_sum = in_cksum_tcp(ip_header.ip_src.s_addr, ip_header.ip_dst.s_addr, (unsigned short *)tcp_buff_fake, tcp_fake_len);
	memcpy(tcp_buff_fake, &tcp_header_fake, sizeof(struct tcphdr));
	unsigned int send_fake_len = tcp_fake_len + sizeof(struct ip); 
	
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip_header.ip_dst.s_addr;
	
	int raw_query_socket;
	
	if ((raw_query_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("raw socket");
		exit(1);
	}
	
	const int on = 1;
	if (setsockopt(raw_query_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt");
		close(raw_query_socket);
		exit(1);
	}
	
	if (sendto(raw_query_socket, send_buff_fake, send_fake_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		close(raw_query_socket);
		exit(1);
	}
	
	if (sendto(raw_query_socket, send_buff_segment1, send_len_segment1, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		close(raw_query_socket);
		exit(1);
	}
	
	if (sendto(raw_query_socket, send_buff_fake, send_fake_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		close(raw_query_socket);
		exit(1);
	}
	
	if (sendto(raw_query_socket, send_buff_segment2, send_len_segment2, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		close(raw_query_socket);
		exit(1);
	}
	
	close(raw_query_socket);
}

void send_rst(char *buff, int len)
{
	struct tcphdr tcp;
	struct ip ip;
	u_char rst_buff[4096] = {0};
	u_char *ip_buff = buff + sizeof(struct ether_header);
	memcpy(&ip, ip_buff, sizeof(struct ip));
	u_char *tcp_buff = ip_buff + sizeof(struct ip);
	memcpy(&tcp, tcp_buff, sizeof(tcp));
	tcp.th_flags = TH_RST;
	tcp.th_seq = tcp.th_ack;
	tcp.th_ack = htonl(0);
	tcp.th_sport = htons(12345);
	tcp.th_dport = htons(53);
	tcp.th_sum = 0;
	memcpy(rst_buff, &tcp, sizeof(struct tcphdr));
	int tcp_hdr_len = tcp.th_off * 4;
	tcp.th_sum = in_cksum_tcp(ip.ip_src.s_addr, ip.ip_dst.s_addr, (unsigned short *)rst_buff, tcp_hdr_len);
	memcpy(rst_buff, &tcp, tcp_hdr_len);
	int raw_tcp_socket;
	if ((raw_tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		perror("raw rst socket");
		exit(1);
	}
	
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_src.s_addr;
	
	if (sendto(raw_tcp_socket, rst_buff, tcp_hdr_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		perror("sendto");
		close(raw_tcp_socket);
		exit(1);
	}
	
	close(raw_tcp_socket);
}

const char* print_dns_type(unsigned short type)
{
	switch(type)
	{
		case 1:
			return "A";
		case 2:
			return "NS";
		case 5:
			return "CNAME";
	}
	return "NotSupport";
}

const char* print_class_type(unsigned short type)
{
	switch(type)
	{
		case 1:
			return "IN";
	}
	return "NotSupport";
}

u_char* print_qname(u_char *buff, u_char *full_dns_buff)
{
	u_char *temp_buff = buff;
	u_char *ptr_buff = NULL;
	u_char segmen_len = *temp_buff++;
	while(segmen_len != 0)
	{
		if(segmen_len == 0xC0)
		{
			if(ptr_buff == NULL)
			{
				ptr_buff = temp_buff + 1;
			}
			u_char offset = *temp_buff;
			temp_buff = full_dns_buff + offset;
		}
		else
		{
			for(u_char i=segmen_len; i>0; i--)
			{
				putchar(*temp_buff);
				temp_buff++;
			}
			putchar('.');
		}
		segmen_len = *temp_buff++;
	}
	if(ptr_buff)
	{
		return ptr_buff;
	}
	return temp_buff;
}

void print_dns_answer(char *buff, int len)
{
	u_char send_buff[4096] = {0};
	u_char *tcp_buff = buff + sizeof(struct ether_header) + sizeof(struct ip);
	struct tcphdr tcp;
	memcpy(&tcp, tcp_buff, sizeof(tcp));
	if(tcp.th_flags == TH_RST)
	{
		printf("connect reset by peer\n");
		return;
	}
	printf("connect answer\n");
	send_rst(buff, len);
	
	u_char *tcp_dns_answer = tcp_buff + tcp.th_off * 4;
	u_char *dns_answer = tcp_dns_answer + sizeof(unsigned short);
	struct dns_answer_hdr_t dns_answer_hdr;
	memcpy(&dns_answer_hdr, dns_answer, sizeof(dns_answer_hdr));
	unsigned short flags = ntohs(dns_answer_hdr.flags);
	if((flags & 0x000F) == 0)
	{
		if((flags & 0x8000) == 0x8000)
		{
			unsigned short questioncount = ntohs(dns_answer_hdr.questioncount);
			printf(";; QUESTION SECTION:\n");
			if(questioncount == 1)
			{
				u_char *query_buff = dns_answer + sizeof(dns_answer_hdr);
				putchar(';');
				query_buff = print_qname(query_buff, dns_answer);
				putchar('\t');
				struct dns_answer_query_t dns_answer_query;
				memcpy(&dns_answer_query, query_buff, sizeof(dns_answer_query));
				unsigned short dns_type = ntohs(dns_answer_query.type);
				unsigned short class_type = ntohs(dns_answer_query.class_type);
				printf("%s\t", print_class_type(class_type));
				printf("%s\n", print_dns_type(dns_type));
				putchar('\n');
				
				u_char *anwser_buff = query_buff + sizeof(dns_answer_query);
				unsigned short answercount = ntohs(dns_answer_hdr.answercount);
				for(int i=0; i< answercount; i++)
				{
					anwser_buff = print_qname(anwser_buff, dns_answer);
					putchar('\t');
					struct dns_answer_query_t dns_answer_query;
					memcpy(&dns_answer_query, anwser_buff, sizeof(dns_answer_query));
					unsigned short dns_type = ntohs(dns_answer_query.type);
					unsigned short class_type = ntohs(dns_answer_query.class_type);
					anwser_buff += sizeof(dns_answer_query);
					unsigned int ttl = 0;
					memcpy(&ttl, anwser_buff, sizeof(ttl));
					ttl = ntohl(ttl);
					anwser_buff += sizeof(ttl);
					unsigned short data_len = 0;
					memcpy(&data_len, anwser_buff, sizeof(data_len));
					data_len = ntohs(data_len);
					anwser_buff += sizeof(data_len);
					printf("%u\t", ttl);
					printf("%s\t", print_class_type(class_type));
					printf("%s\t", print_dns_type(dns_type));
					
					if(dns_type == 1)
					{
						if(data_len == 4)
						{
							printf("%u.%u.%u.%u",
							*anwser_buff, 
							*(anwser_buff+1),
							*(anwser_buff+2),
							*(anwser_buff+3)
							);
						}
						else{
							printf("Not IPv4 Address");
						}
					}
					else
					{
						print_qname(anwser_buff, dns_answer);
					}
					anwser_buff += data_len;
					putchar('\n');
				}
			}
			else
			{
				printf("multiquery is not support.\n");
			}
		}
		else
		{
			printf("this is not a dns answer reponse.\n");
		}
	}
	else
	{
		printf("answer has error:%u\n", flags & 0x000F);
		if((flags & 0x000F)==3)
		{
			printf("no such name\n");
		}
	}
}

void *pth_answer_dns(void *arg)
{
	struct sock_filter psh_filter[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 14, 0, 0x000086dd },
		{ 0x15, 0, 13, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 11, 0x00000006 },
		{ 0x28, 0, 0, 0x00000014 },
		{ 0x45, 9, 0, 0x00001fff },
		{ 0xb1, 0, 0, 0x0000000e },
		{ 0x50, 0, 0, 0x0000001b },
		{ 0x15, 1, 0, 0x00000018 },
		{ 0x15, 0, 5, 0x00000004 },
		{ 0x48, 0, 0, 0x0000000e },
		{ 0x15, 0, 3, 0x00000035 },
		{ 0x48, 0, 0, 0x00000010 },
		{ 0x15, 0, 1, BIND_SOCKET },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	};
	
	struct sock_fprog psh_filter_bpf = {
			.len = sizeof(psh_filter)/sizeof(struct sock_filter),
			.filter = psh_filter,
	};
	
	int cap_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	if(cap_socket < 0)
	{
		perror("raw socket");
		exit(1);
	}
	
	cap_fix_bug(cap_socket);
	
	printf("anwser dns pthread started!\n");
	
	int ret = setsockopt(cap_socket, SOL_SOCKET, SO_ATTACH_FILTER, &psh_filter_bpf, sizeof(psh_filter_bpf));
	
	if(ret < 0)
	{
		perror("setsockopt");
		close(cap_socket);
		exit(1);
	}
	
	u_char buffer_ans[4096] = {0};
	
	int recv_len = recvfrom(cap_socket, buffer_ans, sizeof(buffer_ans), 0, NULL, NULL);
	if(recv_len < 0)
	{
		perror("recv ack");
		close(cap_socket);
		exit(1);
	}
	for(int i = 0; i < recv_len; i++)
	{
		if(i % 16 == 0)
			printf("\n");
		printf("%02X ", buffer_ans[i]);
	}
	printf("\n");
	print_dns_answer(buffer_ans, recv_len);
	close(cap_socket);
}

void *pth_query_dns(void *arg)
{
	struct sock_filter ack_filter[] = {
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 13, 0, 0x000086dd },
		{ 0x15, 0, 12, 0x00000800 },
		{ 0x30, 0, 0, 0x00000017 },
		{ 0x15, 0, 10, 0x00000006 },
		{ 0x28, 0, 0, 0x00000014 },
		{ 0x45, 8, 0, 0x00001fff },
		{ 0xb1, 0, 0, 0x0000000e },
		{ 0x50, 0, 0, 0x0000001b },
		{ 0x15, 0, 5, 0x00000010 },
		{ 0x48, 0, 0, 0x0000000e },
		{ 0x15, 0, 3, BIND_SOCKET },
		{ 0x48, 0, 0, 0x00000010 },
		{ 0x15, 0, 1, 0x00000035 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	};

	struct sock_fprog ack_filter_bpf = {
			.len = sizeof(ack_filter)/sizeof(struct sock_filter),
			.filter = ack_filter,
	};
	
	int cap_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	if(cap_socket < 0)
	{
		perror("raw socket");
		exit(1);
	}
	
	cap_fix_bug(cap_socket);
	
	printf("query dns pthread started!\n");
	
	int ret = setsockopt(cap_socket, SOL_SOCKET, SO_ATTACH_FILTER, &ack_filter_bpf, sizeof(ack_filter_bpf));
	
	if(ret < 0)
	{
		perror("setsockopt");
		close(cap_socket);
		exit(1);
	}
	
	u_char buffer[4096] = {0};
	
	int recv_len = recvfrom(cap_socket, buffer, sizeof(buffer), 0, NULL, NULL);
	if(recv_len < 0)
	{
		perror("recv ack");
		close(cap_socket);
		exit(1);
	}
	close(cap_socket);
	pthread_t tid_pr_;
	if(pthread_create(&tid_pr_, NULL, pth_answer_dns, NULL) != 0)
	{
		printf("anwser dns pthread start failed!\n");
		exit(1);
	}
	char *qname = strdup((char*)arg);
	construct_dns_query_packet_and_send(buffer, recv_len, qname);
	free(qname);
	pthread_join(tid_pr_, NULL);
}

int query_sock;
void start_query()
{
	if( (query_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		perror("dns socket");
		exit(1);
	}
	
	int optval = 1;
	setsockopt(query_sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
	
	struct sockaddr_in queryAddress, localAddress;
	memset(&localAddress, 0, sizeof(localAddress));
	localAddress.sin_family = AF_INET;
	localAddress.sin_port = htons(BIND_SOCKET);
	localAddress.sin_addr.s_addr = INADDR_ANY;
	
	if (bind(query_sock, (struct sockaddr *)&localAddress, sizeof(localAddress)) == -1)
	{
		perror("Failed to bind");
		close(query_sock);
		exit(1);
	}
	
	memset(&queryAddress, 0, sizeof(queryAddress));
	queryAddress.sin_family = AF_INET;
	queryAddress.sin_port = htons(53);
	queryAddress.sin_addr.s_addr = inet_addr("8.8.8.8");
	
	if(connect(query_sock, (struct sockaddr *)&queryAddress, sizeof(queryAddress)) == -1)
	{
		perror("Failed to connect");
		close(query_sock);
		exit(1);
	}
}

int main(int argc,char** argv)
{
	pthread_t tid_pr;
	if(pthread_create(&tid_pr, NULL, pth_query_dns, (void*)argv[1]) != 0)
	{
		printf("query dns pthread start failed!\n");
		exit(1);
	}
	
	sleep(1);
	
	start_query();
	
	pthread_join(tid_pr, NULL);
	close(query_sock);
    return 0;
}