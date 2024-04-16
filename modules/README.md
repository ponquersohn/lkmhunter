# Reason
This is a simple POC module to dump processes directly from kernel to a file.

Its really usefull to hunt rootkits and hidden processes. Its easy to use.

# Usage
```
make && sudo insmod lkmhunter.ko output_path=/tmp/output.txt && rmmod lkmhunter.ko
make -C /lib/modules/5.4.0-146-generic/build M=/home/ponq/lkmhunter modules
make[1]: Entering directory '/usr/src/linux-headers-5.4.0-146-generic'
  CC [M]  /home/ponq/lkmhunter/lkmhunter.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC [M]  /home/ponq/lkmhunter/lkmhunter.mod.o
  LD [M]  /home/ponq/lkmhunter/lkmhunter.ko
make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-146-generic'
```

And then simply dmesg:
```
# dmesg
...
[  268.896792] LKMHunter starting.
[  268.896827] pid: 1 ppid: 0 state: 1 program: systemd
[  268.896836] pid: 2 ppid: 0 state: 1 program: kthreadd
[  268.896845] pid: 3 ppid: 2 state: 1026 program: rcu_gp
[  268.896853] pid: 4 ppid: 2 state: 1026 program: rcu_par_gp
[  268.896861] pid: 5 ppid: 2 state: 1026 program: kworker/0:0
[  268.896870] pid: 6 ppid: 2 state: 1026 program: kworker/0:0H
[  268.896878] pid: 7 ppid: 2 state: 1026 program: kworker/u256:0
... and so on
```

No way the pid can be hidden from here. 


# Notes
## Hunting hidden modules
There are multiple ways a rootkit module can hide itself from a user. Most (if not all today) rely on hiding the module from lsmod command. 
