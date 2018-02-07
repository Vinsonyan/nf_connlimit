#Makefile for network objece(s) module

#netobj core
obj-$(CONFIG_NETWORK_OBJECT) := class_core.o

addrrlp-objs := addrgrp_rlp_std.o addrgrp_rlp_api.o rlp.o 
servobj-objs := servobj_std.o servobj_api.o
servgrp-objs := servgrp_std.o servgrp_api.o
connlimits-objs := connlimit.o xt_cclimit.o xt_nclimit.o

obj-$(CONFIG_NETOBJ_ADDRES_TYPE) += addrrlp.o
obj-$(CONFIG_NETOBJ_SERVICE_TYPE) += servobj.o
obj-$(CONFIG_NETOBJ_SERVGRP_TYPE) += servgrp.o
oj-$(CONFIG_NETOBJ_CONNLIMIT_TYPE) += connlimits.o
