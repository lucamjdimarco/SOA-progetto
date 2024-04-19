ifndef KERNELDIR
	KERNELDIR  := /lib/modules/$(shell uname -r)/build
endif

obj-m += ref.o
obj-m += hash.o
obj-m += func_aux.o 
ref-objs := utils/hash.o utils/func_aux.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

#install:
#	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
#	/sbin/depmod -ae
