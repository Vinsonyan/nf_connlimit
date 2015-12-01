#ifndef __CONNLIMIT_H__
#define __CONNLIMIT_H__

#ifndef CONNLIMIT_DEBUG
#define CONNLIMIT_DEBUG
#endif

#define CONNLIMIT_NAME_LEN	(32 *3)

/* timings are in milliseconds. */
#define XT_LIMIT_SCALE 10000

#define MAX_CPJ (0xFFFFFFFF / (HZ*60*60*24))

/* Repeated shift and or gives us all 1s, final shift and add 1 gives
 * us the power of 2 below the theoretical max, so GCC simply does a
 * shift. */
#define _POW2_BELOW2(x) ((x)|((x)>>1))
#define _POW2_BELOW4(x) (_POW2_BELOW2(x)|_POW2_BELOW2((x)>>2))
#define _POW2_BELOW8(x) (_POW2_BELOW4(x)|_POW2_BELOW4((x)>>4))
#define _POW2_BELOW16(x) (_POW2_BELOW8(x)|_POW2_BELOW8((x)>>8))
#define _POW2_BELOW32(x) (_POW2_BELOW16(x)|_POW2_BELOW16((x)>>16))
#define POW2_BELOW32(x) ((_POW2_BELOW32(x)>>1) + 1)

#define CREDITS_PER_JIFFY POW2_BELOW32(MAX_CPJ)

#ifdef __KERNEL__

#define SIP_HASH_SHIFT	10
#define SIP_HASH_SIZE	( 1 << SIP_HASH_SHIFT )
#define SIP_HASH_MASK	( SIP_HASH_SIZE - 1 )

/* Get current time and format for print log */
#define CONNLIMIT_SHOW_TIME(time_t_val, buf) ({ \
                struct tm res; \
                int count = 0; \
                time_to_tm(time_t_val, 0, &res); \
                res.tm_year += 1900; \
                res.tm_mon += 1; \
                count = scnprintf(buf, PAGE_SIZE, \
                                    "%ld/%.2d/%.2d %.2d:%.2d:%.2d", \
                                    res.tm_year, res.tm_mon, res.tm_mday, \
                                    res.tm_hour, res.tm_min, res.tm_sec);\
                count; \
})
#endif

typedef struct rate_unit {
	u_int32_t 	credit;
	u_int32_t 	credit_cap, cost;
	unsigned long 	prev;	/* last modification */

} rate_unit_t;

/* user to kernel use by socktopet struct */
typedef struct connlimit_cfg {
	/* curconn limit parameters */
	u_int32_t		limits;
	u_int32_t 	limitp;

	/* new conn limit parameters */
	u_int32_t 	avgs, brusts;
	u_int32_t 	avgp, brustp;
	
	/* global parameters */
	u_int8_t 		log;

	/* recalculate rate for newlimit */
	rate_unit_t 	rs, rp;
	
} connlimit_cfg_t;

typedef struct connlimit_request {
	char 			name[CONNLIMIT_NAME_LEN];
	connlimit_cfg_t 	cfg;
} connlimit_request_t;

#ifdef __KERNEL__
/* kernel vir config layer struct */
typedef struct connlimit_item {
	struct hlist_node 	hnode;
	char 			name[CONNLIMIT_NAME_LEN];
	connlimit_cfg_t 	*cfg;
	atomic_t		refcnt;
	
} connlimit_item_t;

extern connlimit_cfg_t *connlimit_get_cfg_rcu(unsigned long addr);
extern unsigned long connlimit_find_obj(const char *name);
extern void connlimit_release_obj(unsigned long addr);
extern unsigned int connlimit_ip_hash(union nf_inet_addr u, u_int8_t family);
extern void connlimit_get_time(char *tbuff);

#endif /* __KERNEL__ */
#endif	/* __CONNLIMIT_H__ */
