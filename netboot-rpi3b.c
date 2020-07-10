/* Network boot helper for the Raspberry Pi 3 Model B.
 *
 * SPDX-License: MIT
 *
 * Copyright (C) 2020 Petr Tesarik <ptesarik@suse.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>

static char pcap_errbuf[PCAP_ERRBUF_SIZE];

/* 236 bytes BOOTP plus 84 bytes DHCP extensions */
#define DHCP_LEN	(236 + 84)

#define CAPTURE_LEN				\
	(sizeof(struct ether_header) +		\
	 sizeof(struct iphdr) +			\
	 sizeof(struct udphdr) +		\
	 DHCP_LEN)

/* Use a smallish capture buffer.
 * The kernel apparently needs at least 256k.
 */
#define PCAP_BUFFER_SIZE	256*1024

/* It doesn't matter which packet is sent to the Raspberry Pi, as long
 * as the target MAC address matches or is broadcast.
 * However, it must also be delivered, and some switches may analyze
 * network traffic and silently drop whatever they consider invalid.
 *
 * So, I was looking for something that:
 *   - operates on Layer 2 (because the target IP address is not yet known),
 *   - does not do any harm to other hosts in the network,
 *   - is commonly used,
 *   - is preferably not broadcast.
 *
 * As it happens, Wake-on-LAN packets have all these properties.
 */

#define ETHER_TYPE_WOL	0x842

#define MAGIC_TIMES	16
struct magic_packet
{
	struct ether_header header;
	struct ether_addr sync;
	struct ether_addr addr[MAGIC_TIMES];
};

struct tasklink {
	struct tasklink *next, *prev;
};

struct task {
	struct tasklink link;
	pthread_t thread;
	struct magic_packet pkt;
};

/* Finished tasks. */
static struct tasklink finished = {
	.next = &finished,
	.prev = &finished,
};
static pthread_mutex_t finished_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t finished_cond = PTHREAD_COND_INITIALIZER;

/* Allocate as little stack space as possible */
#define STACK_SIZE	(16*1024)

static pthread_attr_t thread_attr;
static pthread_t reaper;

static void add_task(struct tasklink *list, struct task *task)
{
	struct tasklink *prev = list->prev;
        list->prev = &task->link;
        task->link.next = list;
        task->link.prev = prev;
        prev->next = &task->link;
}

static void del_task(struct task *task)
{
	task->link.next->prev = task->link.prev;
	task->link.prev->next = task->link.next;
}

static void finish_task(struct task *task)
{
	pthread_mutex_lock(&finished_lock);
	add_task(&finished, task);
	pthread_cond_signal(&finished_cond);
	pthread_mutex_unlock(&finished_lock);
}

static void *reaper_func(void *arg)
{
	int res;

	pthread_mutex_lock(&finished_lock);
	for (;;) {
		res = pthread_cond_wait(&finished_cond, &finished_lock);
		if (res) {
			fprintf(stderr, "Wait for finished threads: %s\n",
				strerror(res));
			exit(1);
		}

		while (finished.next != &finished) {
			struct task *task = (struct task*)finished.next;
			void *retval;

			res = pthread_join(task->thread, &retval);
			if (res)
				fprintf(stderr,
					"WARNING: Cannot join thread: %s\n",
					strerror(res));
			del_task(task);
			free(task);
		}
	}
}

static int init_threads(void)
{
	int res;

	res = pthread_attr_init(&thread_attr);
	if (res) {
		fprintf(stderr, "pthread_attr_init: %s\n",
			strerror(res));
		return 1;
	}
	pthread_attr_setstacksize(&thread_attr, STACK_SIZE);

	res = pthread_create(&reaper, &thread_attr, reaper_func, NULL);
	if (res) {
		fprintf(stderr, "Cannot create reaper thread: %s\n",
			strerror(res));
		return 1;
	}

	return 0;
}

/* Network interface index. */
static int ifindex;

/* Our hardware address */
static struct ifreq ownaddr;

/* Raw socket for output. */
static int rawfd;

static int init_raw(const char *ifname)
{
	rawfd = socket(PF_PACKET, SOCK_RAW, 0);
	if (rawfd < 0) {
		perror("Cannot create raw socket");
		return 1;
	}

	if (strlen(ifname) >= IFNAMSIZ) {
		fprintf(stderr, "Maximum interface name is %d bytes!\n",
			(int)IFNAMSIZ - 1);
		return 1;
	}
	strcpy(ownaddr.ifr_name, ifname);

	if (ioctl(rawfd, SIOCGIFINDEX, &ownaddr) < 0) {
		perror("Cannot get interface index");
		return 1;
	}
	ifindex = ownaddr.ifr_ifindex;

	if (ioctl(rawfd, SIOCGIFHWADDR, &ownaddr) < 0) {
		perror("Cannot obtain own hardware address");
		return 1;
	}

	return 0;
}

static void make_wol_packet(struct magic_packet *pkt,
			    const struct ether_addr *host)
{
	int i;

	/* Ethernet header: */
	memcpy(&pkt->header.ether_dhost, host, ETH_ALEN);
	memcpy(&pkt->header.ether_shost, ownaddr.ifr_hwaddr.sa_data, ETH_ALEN);
	pkt->header.ether_type = htons(ETHER_TYPE_WOL);

	/* And WOL payload: */
	memset(&pkt->sync, 0xff, ETH_ALEN);
	for (i = 0; i < MAGIC_TIMES; ++i)
		memcpy(&pkt->addr[i], host, ETH_ALEN);
}

static void *wol_func(void *arg)
{
	struct task *self = arg;
	struct sockaddr_ll dest;
	int i;
	int res;

	memset (&dest, 0, sizeof dest);
	dest.sll_family = AF_PACKET;
	dest.sll_ifindex = ifindex;
	dest.sll_halen = ETH_ALEN;
	memcpy(&dest.sll_addr, &self->pkt.addr[0], ETH_ALEN);

	for (i = 2; i; --i) {
		usleep(600000);
		res = sendto(rawfd, &self->pkt, sizeof self->pkt, 0,
			     (struct sockaddr*) &dest, sizeof dest);
		if (res < 0) {
			fprintf(stderr, "WARNING: Cannot send WOL: %s\n",
				strerror(errno));
		}
	}

	finish_task(self);
	return NULL;
}

static void pkt_handler(u_char *user, const struct pcap_pkthdr *hdr,
			const u_char *bytes)
{
	struct ether_header *eth = (struct ether_header*)bytes;
	int res;

	if (hdr->caplen < sizeof *eth)
		return;

	printf("DHCP request from %02x:%02x:%02x:%02x:%02x:%02x\n",
	       eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
	       eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

	struct task *task;
	task = malloc(sizeof *task);
	if (!task) {
		fprintf(stderr, "WARNING: Cannot allocate WOL: %s\n",
			strerror(errno));
		return;
	}
	make_wol_packet(&task->pkt, (struct ether_addr*) &eth->ether_shost);

	res = pthread_create(&task->thread, &thread_attr,
			     wol_func, task);
	if (res) {
		fprintf(stderr, "WARNING: Cannot create WOL thread: %s\n",
			strerror(res));
		free(task);
		return;
	}
}

static pcap_t *init_capture(const char *ifname)
{
	pcap_t *pcap;

	pcap = pcap_create(ifname, pcap_errbuf);
	if (!pcap) {
		fprintf(stderr, "Cannot open capture: %s\n", pcap_errbuf);
		return NULL;
	}

	pcap_set_snaplen(pcap, CAPTURE_LEN);
	pcap_set_buffer_size(pcap, PCAP_BUFFER_SIZE);
	pcap_set_promisc(pcap, 0);
	pcap_setdirection(pcap, PCAP_D_IN);
	if (pcap_activate(pcap) < 0) {
		fprintf(stderr, "Cannot activate capture: %s\n",
			pcap_geterr(pcap));
		goto err;
	}

	return pcap;

 err:
	pcap_close(pcap);
	return NULL;
}

static const char filter_str[] =
	/* DHCP Requests are always broadcast */
	"ether broadcast"
	/* OUI b8:27:eb (Raspberry Pi Foundation) */
	" and ether[6:2] == 0xb827 and ether[8:1] == 0xeb"
	/* BOOTP Server UDP packets */
	" and udp dst port 67"
	/* BOOTREQUEST, Ethernet, 6-byte addresses, 0 hops */
	" and udp[8:4] == 0x01010600"
	/* XID */
	" and udp[12:4] == 0x26f30339"
	/* Magic cookie */
	" and udp[244:4] == 0x63825363"
	/* DHCP DISCOVER message type and parameter request list */
	" and udp[248:4] == 0x35010137"
	/* Intel x86PC system architecture (bogus) */
	" and udp[265:4] == 0x5d020000"
	/* Client network interface and machine identifiers (bogus) */
	" and udp[269:4] == 0x5e030102 and udp[273:4] == 0x01611100"
	/* Vendor class identifier (PXEClient) */
	" and udp[293:1] == 0x3c and udp[294:4] == 0x20505845"
	" and udp[298:4] == 0x436c6965 and udp[302:4] == 0x6e743a41"
	" and udp[306:4] == 0x7263683a and udp[310:4] == 0x30303030"
	" and udp[314:4] == 0x303a554e and udp[318:4] == 0x44493a30"
	" and udp[322:4] == 0x30323030 and udp[326:2] == 0x31ff";

static int set_capture_filter(pcap_t *pcap)
{
	struct bpf_program filt;

	/* Set up capture filter */
	if (pcap_compile(pcap, &filt, filter_str,
			 1, PCAP_NETMASK_UNKNOWN) < 0) {
		fprintf(stderr, "Cannot compile filter: %s\n",
			pcap_geterr(pcap));
		return 1;
	}
	if (pcap_setfilter(pcap, &filt) < 0) {
		fprintf(stderr, "Cannot set filter: %s\n",
			pcap_geterr(pcap));
		return 1;
	}
	pcap_freecode(&filt);

	return 0;
}

static int run_capture(const char *ifname)
{
	pcap_t *pcap;

	pcap = init_capture(ifname);
	if (!pcap)
		return 1;

	if (set_capture_filter(pcap))
		return 1;

	return pcap_loop(pcap, -1, pkt_handler, NULL);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
		return 1;
	}

	if (init_raw(argv[1]))
		return 1;

	if (init_threads())
		return 1;

	return run_capture(argv[1]);
}
