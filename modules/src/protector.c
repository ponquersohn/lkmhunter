#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include "kernel_ops.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "lkmhunter.h"

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif
static unsigned long *__sys_call_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);

#else
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
                                          unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
                                            struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;
#endif

unsigned long *
get_syscall_table_bf(void)
{
    unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
#endif
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    return syscall_table;
#else
    unsigned long int i;

    for (i = (unsigned long int)sys_close; i < ULONG_MAX;
         i += sizeof(void *))
    {
        syscall_table = (unsigned long *)i;

        if (syscall_table[__NR_close] == (unsigned long)sys_close)
            return syscall_table;
    }
    return NULL;
#endif
}

// the hook for init_module
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hooked_init_module(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    void *module_image = (int)pt_regs->di;
    unsigned long len = (unsigned long)pt_regs->si;
    const char *param_values = (const char)pt_regs->dx;
#else
#error "And lo, the Lord spoke unto them, saying, 'Verily, verily, I say unto thee, thou shalt not build the module for this platform, for it is not within the scope of my divine plan. Though thou mayest desire to extend thy capabilities and create new things, there are limits and boundaries that must be respected. If thou hast a need or desire to extend the platform, come before me and make thy request known. If it is within my will, I shall grant it unto thee. But if not, thou shalt seek to build it thyself and submit thy work for review. For truly, the work of the hands is but a fleeting thing, but the work of the spirit endures forever.'"
#endif

#else
asmlinkage int
hooked_init_module(void *module_image, unsigned long len,
                const char *param_values;
{
    int ret = orig_getdents64(fd, dirent, count), err;
#endif

    // here the code starts
}

int lkm_protector_init(void)
{
    printk(KERN_INFO "LKMHunters modlist starting.\n");

    __sys_call_table = get_syscall_table_bf();
    if (!__sys_call_table)
        return -1;

    return 0;
}

void lkm_protector_exit(void)
{
    printk(KERN_INFO "LKMHunters modlist unloaded.\n");
}

module_init(lkm_protector_init);
module_exit(lkm_protector_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
