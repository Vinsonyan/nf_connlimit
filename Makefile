#Makefile for connlimit module

connlimits_objs := connlimit.o xt_cclimit.o xt_nclimit.o

obj-m += connlimit.o
obj-m += xt_cclimit.o
obj-m += xt_nclimit.o

KDIR := /home/yanwh/leadsec/up5/themis.kernel

default:
	@echo "Compile modules...."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	find ./ -name '*.o' -o -name '*.ko' -o -name '*.mod.c' -o -name '*.order' -o -name '*symvers' -o -name '.*mod*' -o -name '.*o*' -o -name '.*ko*' | xargs rm -rf  

