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

int init_module(void)
{
    printk(KERN_INFO "LKMProtector starting.\n");

    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "LKMHunter unloaded.\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lech Lachowicz(lech.lachowicz@gmail.com)");
