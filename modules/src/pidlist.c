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

#undef OUTPUT_TO_FILE /// this is currently brokeando

#ifdef OUTPUT_TO_FILE
#include <string.h>

#define OUTPUT_PATH_LEN 1024
static char output_path[OUTPUT_PATH_LEN + 1];
module_param_string(output_path, output_path, OUTPUT_PATH_LEN, 0);
struct file *output_file;
#endif

// will use this to iterate through processes
struct task_struct *task;       /*    Structure defined in sched.h for tasks/processes    */
struct task_struct *task_child; /*    Structure needed to iterate through task children    */
struct list_head *list;         /*    Structure needed to iterate through the list in each task->children struct    */

char cmdline[256];

int init_module(void)
{
    printk(KERN_INFO "LKMHunter starting.\n");

#ifdef OUTPUT_TO_FILE
    if (strlen(output_path) > 0)
    {
        printk(KERN_INFO "Will dump info to: %s\n", output_path);
        output_file = filp_open(output_path, O_WRONLY, 0);
        if (output_file == NULL)
        {
            printk(KERN_INFO "Unable to open file: %s", output_path);
        }
        else
        {
            printk(KERN_INFO "File successfully open: %s", output_path);
        }
    }
#endif

    for_each_process(task)
    {                                                                                                  /*for_each_process() MACRO for iterating through each task in the os located in linux\sched\signal.h*/
        printk(KERN_INFO "pid: %d ppid: %d program: %s\n", task->pid, task_ppid_nr(task), task->comm); /*log parent id/executable name/state*/
#ifdef OUTPUT_TO_FILE
        if (output_file != NULL)
        {
        }
#endif
    }
#ifdef OUTPUT_TO_FILE
    if (output_file != NULL)
    {
        filp_close(output_file, NULL);
    }
#endif
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "LKMHunter unloaded.\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lech Lachowicz(lech.lachowicz@gmail.com)");
