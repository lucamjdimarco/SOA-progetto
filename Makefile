ifndef KERNELDIR
	KERNELDIR  := /lib/modules/$(shell uname -r)/build
endif

#obj-m += the_hash.o
#obj-m += the_func_aux.o 
obj-m += the_ref.o

#the_hash-objs := utils/hash.o
#the_func_aux-objs := utils/func_aux.o
the_ref-objs := utils/hash.o utils/func_aux.o ref.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean