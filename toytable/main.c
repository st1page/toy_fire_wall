#include "../include/common.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <unistd.h>
void print_help()
{
    puts("toytables v0.0.1");
    puts("");
    puts("Usage : toytables addrule [options]");
    puts("        Options:");
    puts("            -p      [tcp|udp|icmp]        protocol by name");
    puts("            -s      address[/mask]        source specification");
    puts("            -d      address[/mask]        destination specification");
    puts("            --sport port                  source port");
    puts("            --dport port                  destination port");
    puts("            --state [new|established]     link state");
    puts("            --action [accept|drop|reject] action");
    puts("        toytables delrule rulenum(count from 1)");
    puts("        toytables setdefaultaction [accept|drop|reject]");
    puts("        toytables rules");
    puts("        toytables connections");
    puts("        toytables logs");
    puts("        toytables help");
}

unsigned int get_addr(char *s)
{
    char *p;
    if (p = strchr(s, '/'))
    {
        puts("warning: mask not supported yet");
        *p = 0;
    }
    unsigned int ret = inet_addr(s);
    if (ret == -1)
    {
        printf("illegal addr %s\n", s);
        exit(1);
    }
    return ret;
}
unsigned short get_port(char *s)
{
    int ret = atoi(s);
    if (ret <= 0 || ret >= 65536)
    {
        printf("illegal port %s\n", s);
        exit(1);
    }
    return ret;
}
ConnectionState get_state(char *s)
{
    if (strcmp(s, "new") == 0)
    {
        return NEW;
    }
    else if (strcmp(s, "established") == 0)
    {
        return ESTABLISHED;
    }
    else
    {
        printf("illegal state %s\n", s);
        exit(1);
    }
}
Proto get_proto(char *s)
{
    if (strcmp(s, "tcp") == 0)
    {
        return TCP;
    }
    else if (strcmp(s, "udp") == 0)
    {
        return UDP;
    }
    else if (strcmp(s, "icmp") == 0)
    {
        return ICMP;
    }
    else
    {
        printf("illegal proto %s\n", s);
        exit(1);
    }
}
RuleAction get_action(char *s)
{
    if (strcmp(s, "accept") == 0)
    {
        return ACCEPT;
    }
    else if (strcmp(s, "reject") == 0)
    {
        return REJECT;
    }
    else if (strcmp(s, "drop") == 0)
    {
        return DROP;
    }
    else
    {
        printf("illegal action %s\n", s);
        exit(1);
    }
}
char *addr2str(unsigned int ip)
{
    static int i = 0;
    static char str[8][20];
    i = (i + 1) & 7;

    if (ip == 0)
    {
        return "any";
    }
    memcpy(str[i], inet_ntoa(*((struct in_addr *)&ip)), 20);
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
    sprintf(str[i], "%hd", port);
    return str[i];
}
void println_rule_title()
{
    printf(rule_fmt, "src_addr", "src_port", "dst_addr", "dst_port", "protocol", "state", "action");
}

void println_rule(Rule rule)
{
    printf("%d\n", rule.connection.dport);
    printf(rule_fmt,
           addr2str(rule.connection.saddr),
           port2str(rule.connection.sport),
           addr2str(rule.connection.daddr),
           port2str(rule.connection.dport),
           proto2str(rule.connection.protocol),
           state2str(rule.state),
           action2str(rule.action));
}
static struct sockaddr_nl local, kpeer;
int kpeerlen = sizeof(struct sockaddr_nl);
int skfd;
void init_local_addr()
{
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    local.nl_groups = 0;
};
void init_kernel_addr()
{
    memset(&kpeer, 0, sizeof(kpeer));
    kpeer.nl_family = AF_NETLINK;
    kpeer.nl_pid = 0;
    kpeer.nl_groups = 0;
};
int init_socket()
{
    skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (skfd < 0)
    {
        printf("can not create a netlink socket\n");
        exit(1);
    }
    return skfd;
}
void init_net_link()
{
    init_local_addr();
    init_kernel_addr();
    init_socket();
    if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0)
    {
        printf("bind() error\n");
        exit(-1);
    }
}
void send_to_kernel(void *data, int len)
{
    printf("sendto kernel, data len: %d\n", len);
    struct nlmsghdr *message;
    message = (struct nlmsghdr *)malloc(sizeof(struct nlmsghdr) + len);
    if (message == NULL)
    {
        printf("malloc() error\n");
        exit(-1);
    }

    memset(message, '\0', sizeof(struct nlmsghdr));
    message->nlmsg_len = NLMSG_SPACE(len);
    message->nlmsg_flags = 0;
    message->nlmsg_type = 0;
    message->nlmsg_seq = 0;
    message->nlmsg_pid = local.nl_pid;

    memcpy(NLMSG_DATA(message), data, len);

    int ret = sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&kpeer, sizeof(kpeer));
    if (!ret)
    {
        perror("sendto:");
        exit(-1);
    }
    // data = NLMSG_DATA(message);
    // NetlinkRequest *req = (NetlinkRequest *)data;
    // printf("netlink recv cmd add rule\n");
    // println_rule_title();
    // println_rule(req->rule);
}
char recive_buffer[1024 * 1024];

NetlinkResponse *recive_from_kernel()
{
    struct nlmsghdr *nlh = (void *)recive_buffer;

    int ret = recvfrom(skfd, nlh, sizeof(recive_buffer), 0, (struct sockaddr *)&kpeer, &kpeerlen);
    if (!ret)
    {
        perror("recvfrom:");
        exit(-1);
    }
    NetlinkResponse *resp = NLMSG_DATA(nlh);
    printf("recv %d bytes from kernel, content\n", ret);
    return resp;
}

void addrule(int argc, char *argv[])
{
    // printf("%d\n", argc);
    // for (int i = 0; i < argc; i++)
    // {
    //     printf("%s\n", argv[i]);
    // }

    static struct option long_options[] =
        {
            {"sport", required_argument, NULL, 1000},
            {"dport", required_argument, NULL, 1001},
            {"state", required_argument, NULL, 1002},
            {"action", required_argument, NULL, 1003},
        };

    NetlinkRequest req;
    NetlinkResponse *resp;

    memset(&req, 0, sizeof(req));
    req.cmd = REQ_ADD_RULE;
    req.rule.action = REJECT;
    req.rule.state = ESTABLISHED;
    req.rule.connection.protocol = 0;
    int index = 0;
    int c = 0;
    while (EOF != (c = getopt_long(argc, argv, "p:s:d:", long_options, &index)))
    {
        switch (c)
        {
        case 'p':
            // printf("p %s\n", optarg);
            req.rule.connection.protocol = get_proto(optarg);
            break;
        case 's':
            // printf("s %s\n", optarg);
            req.rule.connection.saddr = get_addr(optarg);
            break;
        case 'd':
            // printf("d %s\n", optarg);
            req.rule.connection.daddr = get_addr(optarg);
            break;
        case 1000:
            printf("sport %s\n", optarg);
            req.rule.connection.sport = get_port(optarg);
            break;
        case 1001:
            printf("dport %s\n", optarg);
            req.rule.connection.dport = get_port(optarg);
            break;
        case 1002:
            // printf("state %s\n", optarg);
            req.rule.state = get_state(optarg);
            break;
        case 1003:
            // printf("state %s\n", optarg);
            req.rule.action = get_action(optarg);
            break;
        default:
            print_help();
            return;
        }
    }

    puts("add rule");
    println_rule_title();
    println_rule(req.rule);
    println_rule(req.rule);
    println_rule(req.rule);

    if (req.rule.connection.protocol == 0)
    {
        puts("must have protocol! exit!");
        exit(1);
    }
    send_to_kernel(&req, sizeof(req));
    resp = recive_from_kernel();
    if (resp->cmd != RESP_ACK || resp->elem_num != 1)
    {
        puts("wrong resp");
    }
    else
    {
        puts("add success!");
    }
    return;
}
void deleterule(int id)
{
    // printf("%d\n", id);
    NetlinkRequest req;
    NetlinkResponse *resp;

    memset(&req, 0, sizeof(req));
    req.cmd = REQ_DEL_RULE;
    req.id = id;
    send_to_kernel(&req, sizeof(req));
    resp = recive_from_kernel();
    if (resp->cmd != RESP_ACK || resp->elem_num != 1)
    {
        puts("wrong resp");
    }
    else
    {
        puts("delete success!");
    }
}
void showrules()
{
    NetlinkRequest req;
    NetlinkResponse *resp;

    memset(&req, 0, sizeof(req));
    req.cmd = REQ_RULES;
    send_to_kernel(&req, sizeof(req));
    resp = recive_from_kernel();
    println_rule_title();
    for (int i = 0; i < resp->elem_num; i++)
        println_rule(resp->rule[i]);
}
void setdefaultaction(RuleAction action)
{
    NetlinkRequest req;
    NetlinkResponse *resp;

    memset(&req, 0, sizeof(req));
    req.cmd = REQ_SET_DEFAULT_ACTION;
    req.rule.action = action;
    send_to_kernel(&req, sizeof(req));
    resp = recive_from_kernel();
    if (resp->cmd != RESP_ACK || resp->elem_num != 1)
    {
        puts("wrong resp");
    }
    else
    {
        puts("delete success!");
    }
}
void showconnections()
{
}
void showlogs()
{
}
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        print_help();
    }
    init_net_link();
    switch (argv[1][0])
    {
    case 'a':
        addrule(argc - 1, argv + 1);
        break;
    case 'd':
        if (argc != 3)
        {
            puts("unexpected arg counts");
            print_help();
            break;
        }
        int id = atoi(argv[2]);
        deleterule(id);
        break;
    case 'r':
        showrules();
        break;
    case 's':
        if (argc != 3)
        {
            puts("unexpected arg counts");
            print_help();
            break;
        }
        setdefaultaction(get_action(argv[2]));
        break;

    case 'c':
        showconnections();
        break;
    case 'l':
        showlogs();
        break;
    case 'h':
        print_help();
        break;
    default:
        puts("command not found!");
        print_help();
        break;
    }
}
