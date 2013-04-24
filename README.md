# bROOTus
bROOTus is a Linux kernel rootkit that comes as a single LKM (Loadable Kernel Module) and it is totally restricted to kernel 2.6.32. The rootkit is dedicated to educational purposes and is intended to point out some mechanisms on how to manipulate data structures and hook functions in the kernel in order to achieve certain tasks such as file hiding, module hiding, process hiding, socket hiding, packet hiding, keylogging and privilege escalation from within the kernel.

# Documentation
The documentation in PDF format is available [here](http://home.in.tum.de/~strittma/brootus/bROOTus_writeup.pdf)

# Quick start
Make sure you are running a vanilla Linux Kernel (version 2.6.32) and have installed the necessary build tools as well as the Linux header files.

    # Build and insert the rootkit
    make
    insmod rootkit.ko

    # Files beginning with "rootkit_" are hidden by default
    # The rootkit module itself is hidden as well
    # Please consult the documentation for more options

    # Unload the module
    mod_unhide() # Type this in a shell and press CTRL-C afterwards
    rmmod rootkit
