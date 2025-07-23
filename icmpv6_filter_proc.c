
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_NAME "icmpv6_filter"
#define MAX_INPUT 128

static struct nf_hook_ops nfho;
static struct in6_addr match_ip = IN6ADDR_ANY_INIT;
static int icmp_type = 128;
static bool drop = false;

// Netfilter Hook
static unsigned int filter_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state) {
    struct ipv6hdr *ip6h;
    struct icmp6hdr *icmp6h;

    if (!skb)
        return NF_ACCEPT;

    ip6h = ipv6_hdr(skb);
    if (ip6h->nexthdr != IPPROTO_ICMPV6)
        return NF_ACCEPT;

    icmp6h = (struct icmp6hdr *)skb_transport_header(skb);
    if (icmp6h->icmp6_type != icmp_type)
        return NF_ACCEPT;

    if (memcmp(&match_ip, &in6addr_any, sizeof(struct in6_addr)) != 0 &&
        memcmp(&ip6h->saddr, &match_ip, sizeof(struct in6_addr)) != 0)
        return NF_ACCEPT;

    printk(KERN_INFO "%s ICMPv6 type %d from %pI6c\n",
           drop ? "Dropping" : "Logging", icmp_type, &ip6h->saddr);

    return drop ? NF_DROP : NF_ACCEPT;
}

// /proc Write Handler
static ssize_t proc_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos) {
    char input[MAX_INPUT];
    char ip_str[64];
    int type = 128, d = 0;

    if (count > MAX_INPUT - 1)
        return -EINVAL;

    if (copy_from_user(input, buf, count))
        return -EFAULT;

    input[count] = '\0';
    sscanf(input, "type=%d ip=%63s drop=%d", &type, ip_str, &d);

    if (in6_pton(ip_str, -1, match_ip.s6_addr, -1, NULL) == 0)
        match_ip = in6addr_any;

    icmp_type = type;
    drop = d;

    printk(KERN_INFO "Updated filter: type=%d ip=%s drop=%d\n", icmp_type, ip_str, drop);
    return count;
}

static struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
};

static int __init filter_init(void) {
    nfho.hook = filter_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = NFPROTO_IPV6;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);
    proc_create(PROC_NAME, 0666, NULL, &proc_file_ops);
    printk(KERN_INFO "Dynamic ICMPv6 filter module loaded\n");
    return 0;
}

static void __exit filter_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "Dynamic ICMPv6 filter module unloaded\n");
}

module_init(filter_init);
module_exit(filter_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("Dynamic IPv6 ICMPv6 filter with /proc interface");
