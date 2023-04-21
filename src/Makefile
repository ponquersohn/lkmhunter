obj-m += pidlist.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/../build modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/../build clean
