#include "../include/common.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>

struct sock *netlink_socket = NULL;
char *addr2str(unsigned int ip)
{
    static int i = 0;
    static char str[8][20];
    i = (i + 1) & 7;

    if (ip == 0)
    {
        return "any";
    }
    sprintf(str[i], "%pI4", &ip);
    return str[i];
}
char *port2str(unsigned short port)
{
    static int i = 0;
    static char str[8][10];
    i = (i + 1) & 7;

    if (port == 0)
    {
        return "any";
    }
    sprintf(str[i], "%u", port);
    return str[i];
}
void printkln_rule_title(void)
{
    printk(rule_fmt, "src_addr", "src_port", "dst_addr", "dst_port", "protocol", "state", "action");
}

void printkln_rule(Rule rule)
{
    printk(rule_fmt,
           addr2str(rule.connection.saddr),
           port2str(rule.connection.sport),
           addr2str(rule.connection.daddr),
           port2str(rule.connection.dport),
           proto2str(rule.connection.protocol),
           state2str(rule.state),
           action2str(rule.action));
}
void printkln_matches_rule(Rule rule)
{
    printk("matches rule{%s:%s => %s:%s proto:%s state:%s action %s}\n",
           addr2str(rule.connection.saddr),
           port2str(rule.connection.sport),
           addr2str(rule.connection.daddr),
           port2str(rule.connection.dport),
           proto2str(rule.connection.protocol),
           state2str(rule.state),
           action2str(rule.action));
}
typedef struct
{
    struct list_head list;
    Rule rule;
} RuleNode;
int rule_num = 0;
LIST_HEAD(rules);
DEFINE_SPINLOCK(rules_lock);

void add_rule(Rule *rule)
{
    unsigned long tmp = 0;
    RuleNode *r = (RuleNode *)kmalloc(sizeof(RuleNode), GFP_KERNEL);
    memcpy(&(r->rule), rule, sizeof(Rule));
    spin_lock_irqsave(&rules_lock, tmp);
    INIT_LIST_HEAD(&r->list);
    list_add_tail(&(r->list), &rules);
    rule_num++;
    spin_unlock_irqrestore(&rules_lock, tmp);
}
int del_rule(int id)
{
    struct list_head *p, *n;
    RuleNode *r;
    uint32_t i = 0;
    unsigned long tmp = 0;
    printk("%d\n", id);
    spin_lock_irqsave(&rules_lock, tmp);
    list_for_each_safe(p, n, &rules)
    {
        if (++i == id)
        {
            r = list_entry(p, RuleNode, list);
            list_del(p);
            kfree(r);
            rule_num--;
            spin_unlock_irqrestore(&rules_lock, tmp);
            return 1;
        }
    }
    spin_unlock_irqrestore(&rules_lock, tmp);

    printk("del the rule failed, id=%d\n", id);
    return 0;
}
NetlinkResponse *get_rules(void)
{
    struct list_head *p;
    RuleNode *r;
    uint32_t i = 0;
    unsigned long tmp = 0;

    NetlinkResponse *resp = (NetlinkResponse *)kmalloc(response_size(RESP_RULE, rule_num), GFP_KERNEL);
    resp->cmd = RESP_RULE;
    resp->elem_num = rule_num;
    spin_lock_irqsave(&rules_lock, tmp);
    list_for_each(p, &rules)
    {
        r = list_entry(p, RuleNode, list);
        memcpy(&(resp->rule[i++]), &(r->rule), sizeof(Rule));
    }
    spin_unlock_irqrestore(&rules_lock, tmp);

    return resp;
}
RuleAction default_action = ACCEPT;

int match_port(uint16_t port, uint16_t rule_port)
{
    port = htons(port);
    return (port == 0) || (rule_port == 0) || (port == rule_port);
}
int match_addr(uint32_t addr, uint32_t rule_addr)
{
    return (addr == 0) || (rule_addr == 0) || (addr == rule_addr);
}

RuleAction tcp_match_rule(uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport)
{
    struct list_head *c;
    RuleNode *r;
    ConnectionKey rule_conn;
    ConnectionState state;
    RuleAction act;
    unsigned long tmp = 0;
    spin_lock_irqsave(&rules_lock, tmp);

    list_for_each(c, &rules)
    {
        r = list_entry(c, RuleNode, list);
        rule_conn = r->rule.connection;
        state = r->rule.state;
        act = r->rule.action;
        if (match_addr(saddr, rule_conn.saddr) &&
            match_addr(daddr, rule_conn.daddr) &&
            match_port(sport, rule_conn.sport) &&
            match_port(dport, rule_conn.dport))
        {
            printkln_matches_rule(r->rule);
            spin_unlock_irqrestore(&rules_lock, tmp);
            return r->rule.action;
        }
    }
    spin_unlock_irqrestore(&rules_lock, tmp);

    return default_action;
}

int netlink_send(void *data, int len, int pid)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    printk("sendto user, data len: %d", len);

    skb = nlmsg_new(NLMSG_SPACE(len), GFP_ATOMIC);
    if (skb == NULL)
    {
        printk("alloc reply nlmsg skb failed!\n");
        return -1;
    }

    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
    memcpy(NLMSG_DATA(nlh), data, len);

    //NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).dst_group = 0;
    netlink_unicast(netlink_socket, skb, pid, MSG_DONTWAIT);
    return 0;
}

static void netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    char *data = NULL;
    int pid;

    NetlinkRequest *req;
    NetlinkResponse resp;
    NetlinkResponse *resp_ptr;

    uint32_t length = 0;
    if (skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        data = NLMSG_DATA(nlh);
        pid = nlh->nlmsg_pid;

        length = nlh->nlmsg_len - NLMSG_HDRLEN;
        if (data)
        {
            printk("kernel recv from user(%d bytes) : %s\n", length, data);
        }
        if (length >= sizeof(NetlinkRequest))
        {
            req = (NetlinkRequest *)data;
            switch (req->cmd)
            {
            case REQ_CONNS:
                printk("netlink recv cmd show connections\n");
                break;
            case REQ_RULES:
                printk("netlink recv cmd show rules\n");
                resp_ptr = get_rules();
                netlink_send(resp_ptr, response_size(resp_ptr->cmd, resp_ptr->elem_num), pid);
                break;
            case REQ_ADD_RULE:
                printk("netlink recv cmd add rule\n");
                printkln_rule_title();
                printkln_rule(req->rule);
                add_rule(&req->rule);
                resp.cmd = RESP_ACK;
                resp.elem_num = 1;
                netlink_send(&resp, response_size(resp.cmd, resp.elem_num), pid);
                break;
            case REQ_DEL_RULE:
                printk("netlink recv cmd delete rule\n");
                resp.cmd = RESP_ACK;
                resp.elem_num = del_rule(req->id);
                netlink_send(&resp, response_size(resp.cmd, resp.elem_num), pid);
                break;
            case REQ_SET_DEFAULT_ACTION:
                printk("netlink recv cmd set default action\n");
                default_action = req->rule.action;
                resp.cmd = RESP_ACK;
                resp.elem_num = 1;
                netlink_send(&resp, response_size(resp.cmd, resp.elem_num), pid);
                break;
            default:
                printk("netlink: Unknow message recieved\n");
            }
        }
        else
        {
            printk("netlink: Unknow message recieved\n");
        }
    }
}

int act2nfact(RuleAction action)
{
    switch (action)
    {
    case ACCEPT:
        return NF_ACCEPT;
    case DROP:
        return NF_DROP;
    case REJECT:
        return NF_DROP;
    }
    return NF_ACCEPT;
}
inline unsigned int handle_tcp(struct sk_buff *skb, struct iphdr *ip_header)
{
    struct tcphdr *tcp_header = tcp_hdr(skb);
    if (tcp_header->syn)
    {
        // TODO: Match Rules
        printk("NEW TCP Connection %pI4:%u -> %pI4:%u",
               &ip_header->saddr,
               ntohs(tcp_header->source),
               &ip_header->daddr,
               ntohs(tcp_header->dest));
        return act2nfact(tcp_match_rule(ip_header->saddr, ip_header->daddr, tcp_header->source,
                                        tcp_header->dest));
    }
    else
    {
        printk("TCP Package %pI4:%u -> %pI4:%u",
               &ip_header->saddr,
               ntohs(tcp_header->source),
               &ip_header->daddr,
               ntohs(tcp_header->dest));
        return act2nfact(tcp_match_rule(ip_header->saddr, ip_header->daddr, tcp_header->source,
                                        tcp_header->dest));
    }
    return act2nfact(default_action);
}
int handle_udp(struct sk_buff *skb, struct iphdr *ip_header)
{
    struct udphdr *udp_header = udp_hdr(skb);
    printk("UDP Package %pI4:%u -> %pI4:%u",
           &ip_header->saddr,
           ntohs(udp_header->source),
           &ip_header->daddr,
           ntohs(udp_header->dest));
    // show_rules();
    return act2nfact(default_action);
}
int handle_icmp(struct sk_buff *skb, struct iphdr *ip_header)
{
    printk("ICMP Package %pI4 -> %pI4",
           &ip_header->saddr,
           &ip_header->daddr);
    // show_rules();
    return act2nfact(default_action);
}
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    unsigned int ret;
    ip_header = ip_hdr(skb);
    switch (ip_header->protocol)
    {
    case IPPROTO_TCP:
        ret = handle_tcp(skb, ip_header);
        break;
    case IPPROTO_UDP:
        ret = handle_udp(skb, ip_header);
        break;
    case IPPROTO_ICMP:
        ret = NF_ACCEPT;
        break;
    default:
        ret = NF_ACCEPT;
        break;
    }

    return ret;
}
struct netlink_kernel_cfg netlink_cfg = {
    .input = netlink_recv,
};
static struct nf_hook_ops firewall_nfhook_prerouting = {
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .hook = hook_func,
    .priority = NF_IP_PRI_FIRST,
};
static int __init toytable_init(void)
{
    printk("toytable init\n");
    netlink_socket = netlink_kernel_create(&init_net, NETLINK_USER, &netlink_cfg);
    if (!netlink_socket)
    {
        printk(KERN_ERR "can not create a netlink socket\n");
        return -1;
    }
    nf_register_net_hook(&init_net, &firewall_nfhook_prerouting);

    printk("netlink_kernel_create() success, netlink_socket = %p\n", netlink_socket);

    return 0;
}

static void __exit toytable_exit(void)
{
    printk("toytable exit start!\n");
    if (netlink_socket)
    {
        netlink_kernel_release(netlink_socket);
        netlink_socket = NULL;
    }
    nf_unregister_net_hook(&init_net, &firewall_nfhook_prerouting);

    printk("toytable exit success!\n");
}
MODULE_LICENSE("MIT");
MODULE_AUTHOR("st1page");
module_init(toytable_init);
module_exit(toytable_exit);
