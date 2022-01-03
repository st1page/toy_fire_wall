PROJNAME = toytable
obj-m += ${PROJNAME}.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

build:
	#gcc -o ${PROJNAME}.o ${PROJNAME}.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules
