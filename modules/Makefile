SRC=src
UNAME := $(shell uname -r)

.PHONY: all
all:
	cd $(SRC) && $(MAKE) -e UNAME=$(UNAME) all

.PHONY: clean
clean:
	cd $(SRC) && $(MAKE) -e UNAME=$(UNAME) clean

.PHONY: test
test:
	cd $(SRC) && $(MAKE) -e UNAME=$(UNAME) test