// SPDX-License-Identifier: GPL-2.0
/*
 * lkm_mem - raw kernel memory read/write via /proc/lkm/mem
 *
 * Purpose: expose arbitrary kernel-virtual-address memory to a root
 * userspace process, deliberately avoiding the kernel helpers a rootkit is
 * most likely to have hooked. The documented driver for this is Singularity
 * (see ../../singularity.md): its read-side filter zeroes /proc/kcore reads
 * by matching on `file->f_path.dentry->d_name.name == "kcore"`, and its
 * copy_from_kernel_nofault hook returns pre-recorded decoy bytes for any
 * read that lands in the rootkit's own module memory. Both are ftrace hooks
 * on named kernel functions, which means they can only intercept actual
 * calls to those functions -- not inline memory loads.
 *
 * The hot path here is therefore just a volatile byte-pointer dereference
 * in a loop. No calls to copy_from_kernel_nofault, no readelf-of-/proc/kcore,
 * no walk through anything on Singularity's hook list. The dentry name is
 * `mem` under `/proc/lkm/`, which is not in Singularity's string filter.
 *
 * Interface:
 *   /proc/lkm/mem  - seekable rw file; file position == kernel virtual
 *                    address; read()/write() transfer bytes to/from there.
 *
 * Usage:
 *   insmod lkm_mem.ko
 *   # from Python:
 *   with open("/proc/lkm/mem", "rb") as f:
 *       f.seek(0xffffffffc0c12170)
 *       print(f.read(0x40).hex())
 *
 * Writes to read-only kernel pages are made possible by temporarily
 * clearing CR0.WP around each chunk. This is a testbed tool: it can oops
 * the kernel on an invalid address and lets you corrupt arbitrary kernel
 * memory as root. Only load inside the disposable VM.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/overflow.h>
#include <linux/ioctl.h>
#include <linux/version.h>

#define LKM_PROC_DIR  "lkm"
#define LKM_PROC_MEM  "mem"
#define LKM_CHUNK     256    /* bytes per bounce-buffer iteration */

/* ioctl ABI. The read/write-via-seek interface can't carry kernel-space
 * addresses on x86-64 (their top bit set makes them look negative to VFS,
 * which only accepts negative loff_t on files marked FMODE_UNSIGNED_OFFSET
 * -- a flag whose plumbing moved between kernel versions). ioctl sidesteps
 * all of that by shipping the address as an explicit __u64. */
struct lkm_mem_xfer {
	__u64 addr;        /* kernel virtual address, read as unsigned */
	__u64 len;         /* bytes to transfer */
	__u64 user_buf;    /* userspace buffer pointer (cast to __user *) */
};

#define LKM_IOC_MAGIC  'L'
#define LKM_IOC_READ   _IOW(LKM_IOC_MAGIC, 1, struct lkm_mem_xfer)
#define LKM_IOC_WRITE  _IOW(LKM_IOC_MAGIC, 2, struct lkm_mem_xfer)

static struct proc_dir_entry *lkm_dir;
static struct proc_dir_entry *lkm_mem_entry;

/* Basic sanity for kernel-space addresses. Not a correctness guarantee --
 * callers can still oops us with a validly-shaped but unmapped address.
 * See the SAFETY note above. */
static bool addr_range_sane(unsigned long addr, size_t len)
{
	unsigned long end;

	if (len == 0)
		return true;
	if (addr < PAGE_OFFSET)      /* must be kernel-space */
		return false;
	if (check_add_overflow(addr, len, &end))
		return false;
	return true;
}

#if IS_ENABLED(CONFIG_X86_64)
/* Raw CR0 access that bypasses the kernel's write_cr0() helper. The helper
 * enforces CR0 pinning on modern kernels (and is also a named function a
 * sophisticated rootkit might hook); using inline asm sidesteps both. */
static inline unsigned long lkm_read_cr0(void)
{
	unsigned long v;
	asm volatile("mov %%cr0, %0" : "=r"(v));
	return v;
}
static inline void lkm_write_cr0(unsigned long v)
{
	asm volatile("mov %0, %%cr0" : : "r"(v) : "memory");
}
static inline void lkm_disable_wp(void) { lkm_write_cr0(lkm_read_cr0() & ~0x10000UL); }
static inline void lkm_enable_wp(void)  { lkm_write_cr0(lkm_read_cr0() |  0x10000UL); }
#else
static inline void lkm_disable_wp(void) {}
static inline void lkm_enable_wp(void)  {}
#endif

/* Core transfer loops. Shared by both the file read/write interface and the
 * ioctl interface so the "no hookable function in the hot path" guarantee
 * applies equally to both access patterns. Return bytes transferred or a
 * negative errno. */
static ssize_t do_raw_read(unsigned long src, void __user *to, size_t len)
{
	u8 buf[LKM_CHUNK];
	size_t remaining = len;
	size_t total = 0;

	if (!addr_range_sane(src, len))
		return -EFAULT;

	while (remaining > 0) {
		size_t chunk = min(remaining, (size_t)LKM_CHUNK);
		size_t i;

		/* Direct volatile load. No function call, nothing to ftrace. */
		for (i = 0; i < chunk; i++)
			buf[i] = *((volatile u8 *)(src + total + i));

		if (copy_to_user((char __user *)to + total, buf, chunk))
			return total ? (ssize_t)total : -EFAULT;

		total += chunk;
		remaining -= chunk;
	}
	return (ssize_t)total;
}

static ssize_t do_raw_write(unsigned long dst, const void __user *from, size_t len)
{
	u8 buf[LKM_CHUNK];
	size_t remaining = len;
	size_t total = 0;

	if (!addr_range_sane(dst, len))
		return -EFAULT;

	while (remaining > 0) {
		size_t chunk = min(remaining, (size_t)LKM_CHUNK);
		size_t i;

		if (copy_from_user(buf, (const char __user *)from + total, chunk))
			return total ? (ssize_t)total : -EFAULT;

		/* Pin to this CPU and clear write-protect so writes to .text /
		 * .rodata pages work. preempt_disable() keeps us from being
		 * rescheduled onto another CPU with CR0.WP temporarily off. */
		preempt_disable();
		lkm_disable_wp();
		for (i = 0; i < chunk; i++)
			*((volatile u8 *)(dst + total + i)) = buf[i];
		lkm_enable_wp();
		preempt_enable();

		total += chunk;
		remaining -= chunk;
	}
	return (ssize_t)total;
}

static ssize_t lkm_mem_read(struct file *f, char __user *to,
			     size_t len, loff_t *ppos)
{
	ssize_t n = do_raw_read((unsigned long)*ppos, to, len);
	if (n > 0)
		*ppos += n;
	return n;
}

static ssize_t lkm_mem_write(struct file *f, const char __user *from,
			      size_t len, loff_t *ppos)
{
	ssize_t n = do_raw_write((unsigned long)*ppos, from, len);
	if (n > 0)
		*ppos += n;
	return n;
}

static long lkm_mem_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct lkm_mem_xfer x;
	ssize_t n;

	if (copy_from_user(&x, (void __user *)arg, sizeof(x)))
		return -EFAULT;
	if (x.len > (1UL << 30))     /* sanity: 1 GiB per call ought to be plenty */
		return -EINVAL;

	switch (cmd) {
	case LKM_IOC_READ:
		n = do_raw_read(x.addr, (void __user *)(uintptr_t)x.user_buf, x.len);
		break;
	case LKM_IOC_WRITE:
		n = do_raw_write(x.addr, (void __user *)(uintptr_t)x.user_buf, x.len);
		break;
	default:
		return -ENOTTY;
	}
	return n;    /* bytes transferred, or negative errno */
}

static loff_t lkm_mem_llseek(struct file *f, loff_t off, int whence)
{
	/* The "position" is a kernel virtual address. SEEK_SET is the natural
	 * mode. SEEK_CUR is accepted so Python's buffered-reader seekability
	 * probe (lseek(fd, 0, SEEK_CUR)) doesn't disable seeking on the file.
	 * SEEK_END is rejected -- there's no meaningful end of kernel memory. */
	loff_t new_pos;

	switch (whence) {
	case SEEK_SET: new_pos = off;             break;
	case SEEK_CUR: new_pos = f->f_pos + off;  break;
	default:       return -EINVAL;
	}
	f->f_pos = new_pos;
	return new_pos;
}

/* We use f->f_pos as a kernel virtual address, which on x86-64 has the top
 * bit set and therefore looks like a "negative" loff_t to the VFS layer.
 * rw_verify_area() refuses read/write at a negative position unless the
 * file's operations advertise unsigned offsets. In Linux ~6.4+ this moved
 * from the per-file FMODE_UNSIGNED_OFFSET bit (set at open time) to the
 * per-ops FOP_UNSIGNED_OFFSET bit (set declaratively on the ops struct). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops lkm_mem_ops = {
	.proc_read          = lkm_mem_read,
	.proc_write         = lkm_mem_write,
	.proc_lseek         = lkm_mem_llseek,
	.proc_ioctl         = lkm_mem_ioctl,
#ifdef CONFIG_COMPAT
	.proc_compat_ioctl  = lkm_mem_ioctl,
#endif
};
#else
static const struct file_operations lkm_mem_ops = {
	.owner           = THIS_MODULE,
	.read            = lkm_mem_read,
	.write           = lkm_mem_write,
	.llseek          = lkm_mem_llseek,
	.unlocked_ioctl  = lkm_mem_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl    = lkm_mem_ioctl,
#endif
};
#endif

static int __init lkm_mem_init(void)
{
	lkm_dir = proc_mkdir(LKM_PROC_DIR, NULL);
	if (!lkm_dir) {
		pr_err("lkm_mem: proc_mkdir(/proc/" LKM_PROC_DIR ") failed\n");
		return -ENOMEM;
	}
	lkm_mem_entry = proc_create(LKM_PROC_MEM, 0600, lkm_dir, &lkm_mem_ops);
	if (!lkm_mem_entry) {
		pr_err("lkm_mem: proc_create(mem) failed\n");
		remove_proc_entry(LKM_PROC_DIR, NULL);
		return -ENOMEM;
	}
	pr_info("lkm_mem: loaded; interface at /proc/" LKM_PROC_DIR "/" LKM_PROC_MEM "\n");
	return 0;
}

static void __exit lkm_mem_exit(void)
{
	if (lkm_mem_entry)
		remove_proc_entry(LKM_PROC_MEM, lkm_dir);
	if (lkm_dir)
		remove_proc_entry(LKM_PROC_DIR, NULL);
	pr_info("lkm_mem: unloaded\n");
}

module_init(lkm_mem_init);
module_exit(lkm_mem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lkmhunter");
MODULE_DESCRIPTION("Raw kernel memory read/write via /proc/lkm/mem (testbed forensics)");
