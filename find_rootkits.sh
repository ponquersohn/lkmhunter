#!/bin/bash 
workdir=/tmp
echo "The dumbest thing ever. Looking in sys and found:"
comm -13 <(lsmod |cut -d " " -f1|tail -n +2|sort) <(find /sys/module/ -name holders -exec dirname {} \; |xargs -n 1 basename | sort)
echo "Staring prework"
curl --no-progress-meter https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux > $workdir/extract-vmlinux

running_kernel=$(uname -r)

sh $workdir/extract-vmlinux /boot/vmlinuz-$running_kernel > $workdir/vmlinux
echo "Comparing syscalls"
python3 compare_syscalls.py --loaded_kernel_image $workdir/vmlinux --loaded_kernel_sysmap /boot/System.map-$running_kernel

rm -f $workdir/extract-vmlinux $workdir/vmlinux 2>/dev/null