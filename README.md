# LKMHunter - a set of tools to hunt for kernel modules
The purpose is to gather together tools and techniques to hunt for LKMs.

# Examples - total user space
First of all clone Diamorphine + make + load

```
# make
make -C /lib/modules/6.5.0-27-generic/build M=/usr/src/Diamorphine modules
make[1]: Entering directory '/usr/src/linux-headers-6.5.0-27-generic'
warning: the compiler differs from the one used to build the kernel
  The kernel was built by: x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  You are using:           gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  CC [M]  /usr/src/Diamorphine/diamorphine.o
  MODPOST /usr/src/Diamorphine/Module.symvers
  CC [M]  /usr/src/Diamorphine/diamorphine.mod.o
  LD [M]  /usr/src/Diamorphine/diamorphine.ko
  BTF [M] /usr/src/Diamorphine/diamorphine.ko
Skipping BTF generation for /usr/src/Diamorphine/diamorphine.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-6.5.0-27-generic'

# insmod 
diamorphine.ko     diamorphine.mod.o  diamorphine.o      .git/              
# insmod diamorphine.ko 
```

Now have a look at lsmod:

```
# lsmod|grep diamorphine
```
Nothing there.
Lets try to hunt for it with the tool:
```
$ sudo bash find_rootkits.sh 
The dumbest thing ever. Looking in sys and found:
diamorphine
Staring prework
Comparing syscalls
INFO:KernelImage:Syscall kill seems hooked.
INFO:KernelImage:Syscall getdents seems hooked.
INFO:KernelImage:Syscall getdents64 seems hooked.
```

# Example - kernel space
This example uses a module to hunt for PIDs

```
$ cd modules
$ make 
cd src && make all
make[1]: Entering directory '/home/user/lkmhunter/modules/src'
make -C /lib/modules/6.5.0-27-generic/build M=/home/user/lkmhunter/modules/src -I. O= modules
make[2]: Entering directory '/usr/src/linux-headers-6.5.0-27-generic'
warning: the compiler differs from the one used to build the kernel
  The kernel was built by: x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  You are using:           gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0
  CC [M]  /home/user/lkmhunter/modules/src/modlist.o
  CC [M]  /home/user/lkmhunter/modules/src/pidlist.o
  MODPOST /home/user/lkmhunter/modules/src/Module.symvers
  CC [M]  /home/user/lkmhunter/modules/src/modlist.mod.o
  LD [M]  /home/user/lkmhunter/modules/src/modlist.ko
  BTF [M] /home/user/lkmhunter/modules/src/modlist.ko
Skipping BTF generation for /home/user/lkmhunter/modules/src/modlist.ko due to unavailability of vmlinux
  CC [M]  /home/user/lkmhunter/modules/src/pidlist.mod.o
  LD [M]  /home/user/lkmhunter/modules/src/pidlist.ko
  BTF [M] /home/user/lkmhunter/modules/src/pidlist.ko
Skipping BTF generation for /home/user/lkmhunter/modules/src/pidlist.ko due to unavailability of vmlinux
make[2]: Leaving directory '/usr/src/linux-headers-6.5.0-27-generic'
make[1]: Leaving directory '/home/user/lkmhunter/modules/src'
```
And now off we go:
```
$ sudo insmod src/pidlist.ko 
$ sudo dmesg |grep pid
[124971.564356] pid: 1 ppid: 0 program: systemd
[124971.564359] pid: 2 ppid: 0 program: kthreadd
[124971.564361] pid: 3 ppid: 2 program: rcu_gp
[124971.564363] pid: 4 ppid: 2 program: rcu_par_gp
[124971.564364] pid: 5 ppid: 2 program: slub_flushwq
[124971.564366] pid: 6 ppid: 2 program: netns
[124971.564367] pid: 11 ppid: 2 program: mm_percpu_wq
[124971.564369] pid: 12 ppid: 2 program: rcu_tasks_kthre
[124971.564371] pid: 13 ppid: 2 program: rcu_tasks_rude_
[124971.564372] pid: 14 ppid: 2 program: rcu_tasks_trace
[124971.564374] pid: 15 ppid: 2 program: ksoftirqd/0
[124971.564375] pid: 16 ppid: 2 program: rcu_preempt
[124971.564377] pid: 17 ppid: 2 program: migration/0
[124971.564378] pid: 18 ppid: 2 program: idle_inject/0
[124971.564380] pid: 19 ppid: 2 program: cpuhp/0
[124971.564381] pid: 20 ppid: 2 program: cpuhp/1
[124971.564382] pid: 21 ppid: 2 program: idle_inject/1
[124971.564384] pid: 22 ppid: 2 program: migration/1
[124971.564385] pid: 23 ppid: 2 program: ksoftirqd/1
[124971.564387] pid: 25 ppid: 2 program: kworker/1:0H
[124971.564389] pid: 26 ppid: 2 program: cpuhp/2
[124971.564390] pid: 27 ppid: 2 program: idle_inject/2
[124971.564392] pid: 28 ppid: 2 program: migration/2
[124971.564393] pid: 29 ppid: 2 program: ksoftirqd/2
[124971.564395] pid: 31 ppid: 2 program: kworker/2:0H
```

Now that list can be used to look for missing processes.