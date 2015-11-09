#ifndef __NF_PROXY_CFG_H__
#define __NF_PROXY_CFG_H__

#ifndef NF_PROXY_IPTABLES
//#define NF_PROXY_IPTABLES
#endif  /* NF_PROXY_IPTABLES */

#ifdef NF_PROXY_IPTABLES
#define CONFIG_UTM
#endif

/* userspace to kernel sockopt cmds */
#define SO_PROXY_BASE   2167
enum tproxy_so_set_cmds {
        SO_PROXY_SET_PORT = SO_PROXY_BASE,
        SO_PROXY_UNSET_PORT,
	SO_PROXY_SET_MAX,
};

enum tproxy_so_get_cmds {
	SO_PROXY_GET_TUPLE = SO_PROXY_BASE,
#define SO_GET_TUPLE_BY_SK SO_PROXY_GET_TUPLE
        SO_PROXY_PROTO_EXIST,
        SO_PROXY_PORT_SHOW,
        SO_PROXY_GET_MAX,
};

typedef struct sk_tuple {
        u_int8_t        family;
        union nf_inet_addr c, s;
        u_int16_t       client_port, server_port;
} sk_tuple_t;

#ifdef NF_PROXY_IPTABLES
typedef struct  tproxy_port {
        u_int16_t match_port;
        u_int16_t listen_port;
        u_int16_t proxy_flags;
} tproxy_port_t;

typedef struct tproxy_port_set_t {
        u_int8_t        num;
        tproxy_port_t *port_set;
} tproxy_port_set_t;


typedef struct tproxy_port_req {
        u_int8_t        num;
        tproxy_port_t port_set[0];

} tproxy_port_req_t;
#endif	/* NF_PROXY_IPTABLES */

#endif	/* __NF_PROXY_CFG_H__ */
