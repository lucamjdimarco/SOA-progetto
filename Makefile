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
	
mount:
	cd Linux-sys_call_table_address
	make
	./load.sh
	cd ..
	insmod the_ref.ko syscall_table_address=$(shell cat /sys/module/the_usctm/parameters/sys_call_table_address) entry1=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f2) entry2=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f3) entry3=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f4) entry4=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f5) entry5=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f6) entry6=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f7) entry7=$(shell cat /sys/module/the_usctm/parameters/free_entries | cut -d ',' -f8)

clean:
	cd Linux-sys_call_table_address
	make clean
	cd ..
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

unmount:
	rmmod the_usctm.ko
	rmmod the_ref.ko