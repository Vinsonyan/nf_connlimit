#ifndef __ADDR_GROUP_PUB__
#define __ADDR_GROUP_PUB__

#include <linux/types.h>
#include "class_core.h"

#ifndef MAX_OBJ_NAME_LEN
#define MAX_OBJ_NAME_LEN	((32*3)+1)
#endif	/* MAX_OBJ_NAME_LEN */

#ifndef DEBUG
#define DEBUG
#endif	/* DEBUG */

enum {
	ADDROBJ_SRC     = 1 << 0,	/* match source IP address */
	ADDROBJ_DST     = 1 << 1,	/* match destination IP address */
	ADDROBJ_INV 	= 1 << 4,		/* negate */
};

/* Addr group stat */
typedef struct addr_group_stat {
	unsigned int rlp_invalid;

} addr_group_stat_t;

typedef union nf_inet_addr_ipv4 {
	__be32		ip;

} nf_inet_addr_t;

/*add,modify,show addr group object command communication data structure!*/
typedef struct addr_group_unit {
	nf_inet_addr_t left;
	nf_inet_addr_t right;
	size_t	size;
	
} addr_group_unit_t;

typedef struct addr_group_request {
	char group_name[MAX_OBJ_NAME_LEN];
	u_int8_t family;
	u_int32_t num_cell;
	size_t	size;
	addr_group_unit_t cells[0];	/* muse be in here */ 
	
} addr_group_request_t;

#endif	/* __ADDR_GROUP_PUB__  */
