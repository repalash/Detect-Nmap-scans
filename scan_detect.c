//Basic netfilter code from: http://stackoverflow.com/questions/29553990/print-tcp-packet-data
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/time.h>

#define SD_SYN_SCAN_SPEED 256
#define SD_NULL_SCAN_SPEED 8
#define SD_FIN_SCAN_SPEED 8 
#define SD_XMAS_SCAN_SPEED 8

static struct nf_hook_ops nfho;
typedef struct scan_detect_history{
	u32 saddr;
	long int ctr;
	time_t timestamp;// do_gettimeofday
}scan_detect_history;
scan_detect_history sd_syn_scan, sd_fin_scan, sd_null_scan, sd_xmas_scan;

static unsigned int scan_detect_hook_func(const struct nf_hook_ops *ops,
								struct sk_buff *skb,
								const struct net_device *in,
								const struct net_device *out,
								int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u32 saddr, daddr;
	struct timeval current_time;

	do_gettimeofday(&current_time);
	
	if (!skb)
	    return NF_ACCEPT;
	
	iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_TCP)
	    return NF_ACCEPT;

	tcph = tcp_hdr(skb);

	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);

	if(tcph->syn && !(tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin)){
		//detected syn packet
		if(sd_syn_scan.saddr == saddr && sd_syn_scan.timestamp == current_time.tv_sec){
			sd_syn_scan.ctr++;
			if(sd_syn_scan.ctr>=SD_SYN_SCAN_SPEED && sd_syn_scan.ctr%SD_SYN_SCAN_SPEED==0){
				printk("scan_detect: Source: %pI4h, Scan type: SYN, %ld packets this sec\n", &sd_syn_scan.saddr, sd_syn_scan.ctr);
			}
		}else{
			sd_syn_scan.saddr = saddr;
			sd_syn_scan.timestamp = current_time.tv_sec;
			sd_syn_scan.ctr=0;
		}
	}else if(!(tcph->syn || tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin)){
		//detected null packet
		if(sd_null_scan.saddr == saddr && sd_null_scan.timestamp == current_time.tv_sec){
			sd_null_scan.ctr++;
			if(sd_null_scan.ctr>=SD_NULL_SCAN_SPEED && sd_null_scan.ctr%SD_NULL_SCAN_SPEED==0){
				printk("scan_detect: Source: %pI4h, Scan type: NULL, %ld packets this sec\n", &sd_null_scan.saddr, sd_null_scan.ctr);
			}
		}else{
			sd_null_scan.saddr = saddr;
			sd_null_scan.timestamp = current_time.tv_sec;
			sd_null_scan.ctr=0;
		}
	}else if(tcph->fin && !(tcph->urg || tcph->psh || tcph->ack || tcph->rst || tcph->syn)){
		//detected fin packet
		if(sd_fin_scan.saddr == saddr && sd_fin_scan.timestamp == current_time.tv_sec){
			sd_fin_scan.ctr++;
			if(sd_fin_scan.ctr>=SD_FIN_SCAN_SPEED && sd_fin_scan.ctr%SD_FIN_SCAN_SPEED==0){
				printk("scan_detect: Source: %pI4h, Scan type: FIN, %ld packets this sec\n", &sd_fin_scan.saddr, sd_fin_scan.ctr);
			}
		}else{
			sd_fin_scan.saddr = saddr;
			sd_fin_scan.timestamp = current_time.tv_sec;
			sd_fin_scan.ctr=0;
		}
	}else if(tcph->fin && tcph->urg && tcph->psh && !(tcph->ack || tcph->rst || tcph->syn)){
		//detected xmas packet
		if(sd_xmas_scan.saddr == saddr && sd_xmas_scan.timestamp == current_time.tv_sec){
			sd_xmas_scan.ctr++;
			if(sd_xmas_scan.ctr>=SD_XMAS_SCAN_SPEED && sd_xmas_scan.ctr%SD_XMAS_SCAN_SPEED==0){
				printk("scan_detect: Source: %pI4h, Scan type: XMAS, %ld packets this sec\n", &sd_xmas_scan.saddr, sd_xmas_scan.ctr);
			}
		}else{
			sd_xmas_scan.saddr = saddr;
			sd_xmas_scan.timestamp = current_time.tv_sec;
			sd_xmas_scan.ctr=0;
		}
	}
	return NF_ACCEPT;
}

static int __init scan_detect_init(void)
{
	int res;

	nfho.hook = (nf_hookfn *)scan_detect_hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;

	res = nf_register_hook(&nfho);
	if (res < 0) {
		printk("scan_detect: error in nf_register_hook()\n");
		return res;
	}

	printk("scan_detect: module loaded\n");
	return 0;
}

static void __exit scan_detect_exit(void)
{
    nf_unregister_hook(&nfho);
    printk("scan_detect: unloaded module\n");
}

module_init(scan_detect_init);
module_exit(scan_detect_exit);

MODULE_AUTHOR("Palash Bansal");
MODULE_DESCRIPTION("Module for detecting various nmap scans");
MODULE_LICENSE("GPL");