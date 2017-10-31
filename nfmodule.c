#define __KERNEL__
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
static struct nf_hook_ops nfho;         //struct holding set of hook function options

struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};


//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	printk(KERN_INFO "packet got\n");
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	return NF_ACCEPT;
}

int init_module(void)
{
	nfho.hook = hook_func;                       //function to call when conditions below met
	nfho.hooknum = NF_IP_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
	nfho.pf = PF_INET;                           //IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_hook(&nfho);                     //register hook
	return 0;
}

void cleanup_module(void)
{
	nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}
