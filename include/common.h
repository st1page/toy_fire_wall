#ifndef COMMON_H
#define COMMON_H

#define NETLINK_USER (31)
typedef enum
{
    TCP = 1,
    UDP,
    ICMP,
} Proto;
typedef struct
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    Proto protocol;
} ConnectionKey;
typedef enum
{
    NEW = 1,
    ESTABLISHED,
} ConnectionState;
typedef enum
{
    REJECT = 1,
    ACCEPT,
    DROP,
} RuleAction;
typedef struct
{
    ConnectionKey connection;
    ConnectionState state;
    RuleAction action;
} Rule;
const char *rule_fmt = "%-17s%-9s%-17s%-9s%-9s%-12s%-7s\n";

typedef enum
{
    REQ_CONNS = 1,
    REQ_RULES,
    REQ_ADD_RULE,
    REQ_DEL_RULE,
    REQ_SET_DEFAULT_ACTION,
} ReqCmd;
typedef struct
{
    ReqCmd cmd;
    union
    {
        int id;
        Rule rule;
    };
} NetlinkRequest;
typedef enum
{
    RESP_ACK = 1,
    RESP_RULE,
    RESP_CONN,
} RespCmd;

typedef struct
{
    RespCmd cmd;
    int elem_num;
    union
    {
        Rule rule[0];
        ConnectionKey conn[0];
    };
} NetlinkResponse;
unsigned response_size(RespCmd cmd, int elem_num)
{
    switch (cmd)
    {
    case RESP_ACK:
        return sizeof(NetlinkResponse);
    case RESP_CONN:
        return sizeof(NetlinkResponse) + sizeof(ConnectionKey) * elem_num;
    case RESP_RULE:
        return sizeof(NetlinkResponse) + sizeof(Rule) * elem_num;
    }
    return 0;
}
char *proto2str(Proto protocol)
{
    switch (protocol)
    {
    case TCP:
        return "tcp";
    case UDP:
        return "udp";
    case ICMP:
        return "icmp";
    }
    return "NULL";
}
char *state2str(ConnectionState state)
{
    switch (state)
    {
    case ESTABLISHED:
        return "established";
    case NEW:
        return "new";
    }
    return "NULL";
}
char *action2str(RuleAction action)
{
    switch (action)
    {
    case ACCEPT:
        return "accept";
    case DROP:
        return "drop";
    case REJECT:
        return "reject";
    }
    return "NULL";
}

#endif