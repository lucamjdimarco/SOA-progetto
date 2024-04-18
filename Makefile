obj-m += ref.o
ref-objs += utils/hash.o utils/func_aux.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
