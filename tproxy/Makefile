#Makefile for tproxy

obj-m := nf_proxy_tcp.o

KDIR := /home/yanwh/leadsec/Branch_japan/themis.kernel
INCLUDE := /home/yanwh/leadsec/Branch_japan/themis.kernel
default:
	@echo "Compile modules...."
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	find ./ -name '*.o' -o -name '*.ko' -o -name '*.mod.c' -o -name '*.order' -o -name '*symvers' -o -name '.*mod*' -o -name '.*o*' -o -name '.*ko*' | xargs rm -rf  

