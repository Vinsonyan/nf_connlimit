#ifndef __NF_PROXY_H__
#define __NF_PROXY_H__
#include <linux/types.h>
#include "nf_proxy_cfg.h"

#define LEADSEC_VERSION_CODE 16	
#define LEADSEC_VERSION(a, b, c, d) ((a) + (b) + (c) + (d))

#define tproxy_print(flag, format, args...) \
        ((flag) ? printk(KERN_INFO format , ## args) : 0)

#define NF_CT_TPROXY_ZONE	1024
#define SKB_PROUTE_MARK	53556
#define RING_SIZE	1024
#define TPROXY_PROC_PATH "/proc/sys/leadsec/tproxy"

/* ebtable matchs */
struct ebt_connid_info {
        unsigned short zone_id;
        uint8_t invert;
};

#endif	/* __NF_PROXY_H__  */
