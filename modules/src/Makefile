obj-m +=  modlist.o pidlist.o 
 
MODULE_SRC=.
EXTRA_CFLAGS += -I$(MODULE_SRC)

KBUILD_CFLAGS_MODULE += -Werror

UNAME := $(shell uname -r)
KBUILD_DIR := /lib/modules/$(UNAME)/build
PWD := $(shell pwd)
BUILD_DIR := 

all: 
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) $(EXTRA_CFLAGS) O=$(BUILD_DIR) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(PWD) $(EXTRA_CFLAGS) O=$(BUILD_DIR) clean
	

.PHONY: clean