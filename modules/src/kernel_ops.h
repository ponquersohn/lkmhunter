#ifndef __kernel_ops_h
#define __kernel_ops_h

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"};
#endif

#endif //__kernel_ops_h