/*
 * akane hide: make things invisible to non-root callers. A registry of
 * targets (paths, module names, ports) drives kretprobes that filter files,
 * /proc/modules + getdents64, /proc/net/{tcp,udp}{,6}, and memory
 * introspection (/proc/<pid>/{mem,smaps,pagemap} + process_vm_* + mincore).
 *
 * Every hook short-circuits for root, so the controller keeps working while
 * the (non-root) target app is filtered. Each hook attaches best-effort: a
 * failed registration is logged but never fails the module.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/dirent.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/pid.h>

#include "akane.h"

/*
 * Registry: one list per kind. Path matches are exact OR directory-prefix
 * ("/sys/module/akane" also hides "/sys/module/akane/sections").
 */
struct hide_entry {
	struct list_head link;
	u32		 kind;
	u16		 port;		/* TCP_PORT / UDP_PORT */
	char		 name[AKANE_HIDE_NAME_MAX];
};

static LIST_HEAD(path_list);
static LIST_HEAD(module_list);
static LIST_HEAD(tcp_list);
static LIST_HEAD(udp_list);
static DEFINE_SPINLOCK(reg_lock);

static struct list_head *list_for_kind(u32 kind)
{
	switch (kind) {
	case AKANE_HIDE_KIND_PATH:	return &path_list;
	case AKANE_HIDE_KIND_MODULE:	return &module_list;
	case AKANE_HIDE_KIND_TCP_PORT:	return &tcp_list;
	case AKANE_HIDE_KIND_UDP_PORT:	return &udp_list;
	}
	return NULL;
}

static bool kind_is_port(u32 kind)
{
	return kind == AKANE_HIDE_KIND_TCP_PORT ||
	       kind == AKANE_HIDE_KIND_UDP_PORT;
}

static int hide_add(u32 kind, const char *name, u32 port)
{
	struct list_head *head = list_for_kind(kind);
	struct hide_entry *e, *fresh;

	if (!head)
		return -EINVAL;
	if (!kind_is_port(kind) && (!name || !*name))
		return -EINVAL;
	if (kind_is_port(kind) && (port == 0 || port > 0xFFFF))
		return -EINVAL;

	fresh = kzalloc(sizeof(*fresh), GFP_KERNEL);
	if (!fresh)
		return -ENOMEM;
	fresh->kind = kind;
	fresh->port = (u16)port;
	if (name)
		strscpy(fresh->name, name, sizeof(fresh->name));

	spin_lock(&reg_lock);
	list_for_each_entry(e, head, link) {
		bool match = kind_is_port(kind)
			   ? e->port == fresh->port
			   : strcmp(e->name, fresh->name) == 0;
		if (match) {
			spin_unlock(&reg_lock);
			kfree(fresh);
			return -EEXIST;
		}
	}
	list_add(&fresh->link, head);
	spin_unlock(&reg_lock);
	return 0;
}

static int hide_remove(u32 kind, const char *name, u32 port)
{
	struct list_head *head = list_for_kind(kind);
	struct hide_entry *e, *tmp;

	if (!head)
		return -EINVAL;

	spin_lock(&reg_lock);
	list_for_each_entry_safe(e, tmp, head, link) {
		bool match = kind_is_port(kind)
			   ? e->port == (u16)port
			   : (name && strcmp(e->name, name) == 0);
		if (match) {
			list_del(&e->link);
			spin_unlock(&reg_lock);
			kfree(e);
			return 0;
		}
	}
	spin_unlock(&reg_lock);
	return -ENOENT;
}

static bool hide_match_path(const char *path)
{
	struct hide_entry *e;
	bool hit = false;

	if (!path)
		return false;

	spin_lock(&reg_lock);
	list_for_each_entry(e, &path_list, link) {
		size_t nlen = strlen(e->name);

		if (strncmp(path, e->name, nlen) == 0 &&
		    (path[nlen] == '\0' || path[nlen] == '/')) {
			hit = true;
			break;
		}
	}
	spin_unlock(&reg_lock);
	return hit;
}

static bool hide_match_module(const char *name)
{
	struct hide_entry *e;
	bool hit = false;

	if (!name)
		return false;

	spin_lock(&reg_lock);
	list_for_each_entry(e, &module_list, link) {
		if (strcmp(e->name, name) == 0) {
			hit = true;
			break;
		}
	}
	spin_unlock(&reg_lock);
	return hit;
}

static bool match_port(struct list_head *head, u16 port)
{
	struct hide_entry *e;
	bool hit = false;

	spin_lock(&reg_lock);
	list_for_each_entry(e, head, link) {
		if (e->port == port) {
			hit = true;
			break;
		}
	}
	spin_unlock(&reg_lock);
	return hit;
}

static bool hide_match_tcp_port(u16 port)
{
	return match_port(&tcp_list, port);
}

static bool hide_match_udp_port(u16 port)
{
	return match_port(&udp_list, port);
}

static long hide_ioctl(unsigned long arg, bool add)
{
	struct akane_hide_target req;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	req.name[sizeof(req.name) - 1] = '\0';

	if (add)
		return hide_add(req.kind, (const char *)req.name, req.port);
	return hide_remove(req.kind, (const char *)req.name, req.port);
}

long akane_hide_add_handle(unsigned long arg)
{
	return hide_ioctl(arg, true);
}

long akane_hide_remove_handle(unsigned long arg)
{
	return hide_ioctl(arg, false);
}

static int hide_registry_init(void)
{
	static const struct {
		u32 kind;
		const char *name;
	} defaults[] = {
		{ AKANE_HIDE_KIND_PATH,	  "/dev/akane"	     },
		{ AKANE_HIDE_KIND_PATH,	  "/sys/module/akane" },
		{ AKANE_HIDE_KIND_MODULE, "akane"	     },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(defaults); i++) {
		int rc = hide_add(defaults[i].kind, defaults[i].name, 0);

		if (rc && rc != -EEXIST)
			return rc;
	}
	return 0;
}

static void hide_registry_exit(void)
{
	struct list_head *heads[] = {
		&path_list, &module_list, &tcp_list, &udp_list,
	};
	struct hide_entry *e, *tmp;
	size_t i;

	spin_lock(&reg_lock);
	for (i = 0; i < ARRAY_SIZE(heads); i++) {
		list_for_each_entry_safe(e, tmp, heads[i], link) {
			list_del(&e->link);
			kfree(e);
		}
	}
	spin_unlock(&reg_lock);
}

/*
 * Files: hidden paths return -ENOENT. do_filp_open gets a kernel
 * `struct filename *` in x1; the syscall entries use the `fn(struct pt_regs *)`
 * form, so the filename user-pointer is at user_regs->regs[1].
 */
#define HIDE_PATH_PEEK	256

struct hide_open_data {
	bool intercept;
};

static int do_filp_open_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_open_data *d = (struct hide_open_data *)ri->data;
	struct filename *pathname = (struct filename *)regs->regs[1];

	d->intercept = false;
	if (!pathname || akane_is_root())
		return 0;
	if (!hide_match_path(pathname->name))
		return 0;
	d->intercept = true;
	return 0;
}

static int do_filp_open_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_open_data *d = (struct hide_open_data *)ri->data;
	void *ret;

	if (!d->intercept)
		return 0;
	ret = (void *)regs->regs[0];
	if (!IS_ERR(ret))
		return 0;
	regs->regs[0] = (unsigned long)ERR_PTR(-ENOENT);
	return 0;
}

static struct kretprobe filp_open_kp = {
	.handler       = do_filp_open_ret,
	.entry_handler = do_filp_open_pre,
	.data_size     = sizeof(struct hide_open_data),
	.maxactive     = 32,
};

struct hide_path_data {
	bool intercept;
};

static int hide_path_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_path_data *d = (struct hide_path_data *)ri->data;
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
	const char __user *fname;
	char path[HIDE_PATH_PEEK];

	d->intercept = false;
	if (!user_regs || akane_is_root())
		return 0;

	fname = (const char __user *)user_regs->regs[1];
	if (!fname)
		return 0;

	if (strncpy_from_user(path, fname, sizeof(path)) <= 0)
		return 0;
	path[sizeof(path) - 1] = '\0';

	if (hide_match_path(path))
		d->intercept = true;
	return 0;
}

static int hide_path_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_path_data *d = (struct hide_path_data *)ri->data;

	if (d->intercept)
		regs->regs[0] = (unsigned long)(-ENOENT);
	return 0;
}

#define DEFINE_PATH_KRETPROBE(_name)			\
static struct kretprobe _name = {			\
	.handler       = hide_path_ret,			\
	.entry_handler = hide_path_pre,			\
	.data_size     = sizeof(struct hide_path_data),	\
	.maxactive     = 32,				\
}

DEFINE_PATH_KRETPROBE(newfstatat_kp);
DEFINE_PATH_KRETPROBE(statx_kp);
DEFINE_PATH_KRETPROBE(faccessat_kp);
DEFINE_PATH_KRETPROBE(readlinkat_kp);

static bool open_attached;
static bool newfstatat_attached, statx_attached;
static bool faccessat_attached, readlinkat_attached;

static int hide_files_init(void)
{
	int ret;

	filp_open_kp.kp.symbol_name = "do_filp_open";
	ret = register_kretprobe(&filp_open_kp);
	if (ret) {
		pr_err("akane: hide_files: do_filp_open: %d\n", ret);
		return ret;
	}
	open_attached = true;

	newfstatat_kp.kp.symbol_name = "__arm64_sys_newfstatat";
	if (register_kretprobe(&newfstatat_kp) == 0)
		newfstatat_attached = true;

	statx_kp.kp.symbol_name = "__arm64_sys_statx";
	if (register_kretprobe(&statx_kp) == 0)
		statx_attached = true;

	faccessat_kp.kp.symbol_name = "__arm64_sys_faccessat";
	if (register_kretprobe(&faccessat_kp) == 0)
		faccessat_attached = true;

	readlinkat_kp.kp.symbol_name = "__arm64_sys_readlinkat";
	if (register_kretprobe(&readlinkat_kp) == 0)
		readlinkat_attached = true;

	pr_info("akane: hide_files: open=%d stat=%d statx=%d access=%d readlink=%d\n",
		open_attached, newfstatat_attached, statx_attached,
		faccessat_attached, readlinkat_attached);
	return 0;
}

static void hide_files_exit(void)
{
	if (open_attached)
		unregister_kretprobe(&filp_open_kp);
	if (newfstatat_attached)
		unregister_kretprobe(&newfstatat_kp);
	if (statx_attached)
		unregister_kretprobe(&statx_kp);
	if (faccessat_attached)
		unregister_kretprobe(&faccessat_kp);
	if (readlinkat_attached)
		unregister_kretprobe(&readlinkat_kp);
}

/*
 * Modules: drop hidden module names from /proc/modules and getdents64.
 * m_show emits one /proc/modules line; we snapshot seq_file->count before the
 * call and rewind it on return if the line's first token is a hidden name.
 */
struct hide_mshow_data {
	struct seq_file *m;
	size_t		 count_before;
	bool		 track;
};

static int m_show_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_mshow_data *d = (struct hide_mshow_data *)ri->data;
	struct seq_file *m = (struct seq_file *)regs->regs[0];

	d->track = false;
	if (!m || akane_is_root())
		return 0;

	d->m		= m;
	d->count_before = m->count;
	d->track	= true;
	return 0;
}

static int m_show_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_mshow_data *d = (struct hide_mshow_data *)ri->data;
	const char *line, *space;
	size_t line_len, nlen;
	char name[AKANE_HIDE_NAME_MAX];

	if (!d->track || !d->m || !d->m->buf)
		return 0;
	if (d->m->count <= d->count_before)
		return 0;
	if (d->m->count > d->m->size)
		return 0;

	line	 = d->m->buf + d->count_before;
	line_len = d->m->count - d->count_before;

	/* /proc/modules line is "<name> <size> <refcnt> ..."; take token 1. */
	space = memchr(line, ' ', line_len);
	if (!space)
		return 0;
	nlen = space - line;
	if (nlen == 0 || nlen >= sizeof(name))
		return 0;

	memcpy(name, line, nlen);
	name[nlen] = '\0';

	if (hide_match_module(name))
		d->m->count = d->count_before;
	return 0;
}

static struct kretprobe m_show_kp = {
	.handler       = m_show_ret,
	.entry_handler = m_show_pre,
	.data_size     = sizeof(struct hide_mshow_data),
	.maxactive     = 32,
};

struct hide_dents_data {
	void __user *user_buf;
	bool	     intercept;
};

static int getdents64_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_dents_data *d = (struct hide_dents_data *)ri->data;
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];

	d->intercept = false;
	if (!user_regs || akane_is_root())
		return 0;

	d->user_buf  = (void __user *)user_regs->regs[1];
	d->intercept = true;
	return 0;
}

static int getdents64_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_dents_data *d = (struct hide_dents_data *)ri->data;
	long ret = (long)regs->regs[0];
	char *kbuf, *p, *end;
	long new_size;

	if (!d->intercept || ret <= 0)
		return 0;
	if (ret > 16384)			/* cap the GFP_ATOMIC alloc */
		return 0;

	kbuf = kmalloc(ret, GFP_ATOMIC);
	if (!kbuf)
		return 0;

	if (copy_from_user(kbuf, d->user_buf, ret)) {
		kfree(kbuf);
		return 0;
	}

	p   = kbuf;
	end = kbuf + ret;
	while (p + sizeof(struct linux_dirent64) <= end) {
		struct linux_dirent64 *de = (struct linux_dirent64 *)p;
		unsigned short reclen = de->d_reclen;

		if (reclen == 0 || reclen > (unsigned long)(end - p))
			break;
		if (hide_match_module(de->d_name)) {
			memmove(p, p + reclen, end - (p + reclen));
			end -= reclen;
		} else {
			p += reclen;
		}
	}

	new_size = end - kbuf;
	if (new_size != ret) {
		if (copy_to_user(d->user_buf, kbuf, new_size) == 0)
			regs->regs[0] = (unsigned long)new_size;
	}
	kfree(kbuf);
	return 0;
}

static struct kretprobe getdents64_kp = {
	.handler       = getdents64_ret,
	.entry_handler = getdents64_pre,
	.data_size     = sizeof(struct hide_dents_data),
	.maxactive     = 32,
};

static bool dents_attached, mshow_attached;

static int hide_modules_init(void)
{
	getdents64_kp.kp.symbol_name = "__arm64_sys_getdents64";
	if (register_kretprobe(&getdents64_kp) == 0)
		dents_attached = true;

	m_show_kp.kp.symbol_name = "m_show";
	if (register_kretprobe(&m_show_kp) == 0)
		mshow_attached = true;

	pr_info("akane: hide_modules: readdir=%d modules=%d\n",
		dents_attached, mshow_attached);
	return 0;
}

static void hide_modules_exit(void)
{
	if (dents_attached)
		unregister_kretprobe(&getdents64_kp);
	if (mshow_attached)
		unregister_kretprobe(&m_show_kp);
}

/*
 * Net: drop /proc/net/{tcp,udp}{,6} lines whose local or remote port is hidden.
 * Ports print as exactly 4 hex chars; same count-rewind trick as m_show,
 * scanning the emitted bytes for ":HHHH" tokens.
 */
static bool is_hex_char(char c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'A' && c <= 'F') ||
	       (c >= 'a' && c <= 'f');
}

static u16 parse_hex4(const char *p)
{
	u16 v = 0;
	int i;

	for (i = 0; i < 4; i++) {
		char c = p[i];
		u16 d = (c >= '0' && c <= '9') ? c - '0'
		      : (c >= 'A' && c <= 'F') ? 10 + c - 'A'
		      : 10 + c - 'a';
		v = (v << 4) | d;
	}
	return v;
}

/* Scan for ":HHHH" port tokens and ask `match` whether to hide. */
static bool line_has_hidden_port(const char *line, size_t len,
				 bool (*match)(u16))
{
	size_t i = 0;

	while (i + 5 <= len) {
		if (line[i] == ':' &&
		    is_hex_char(line[i + 1]) &&
		    is_hex_char(line[i + 2]) &&
		    is_hex_char(line[i + 3]) &&
		    is_hex_char(line[i + 4]) &&
		    (i + 5 == len || !is_hex_char(line[i + 5]))) {
			if (match(parse_hex4(line + i + 1)))
				return true;
			i += 5;
			continue;
		}
		i++;
	}
	return false;
}

struct net_show_data {
	struct seq_file *m;
	size_t		 count_before;
	bool		 track;
};

static int net_show_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct net_show_data *d = (struct net_show_data *)ri->data;
	struct seq_file *m = (struct seq_file *)regs->regs[0];

	d->track = false;
	if (!m || akane_is_root())
		return 0;

	d->m		= m;
	d->count_before = m->count;
	d->track	= true;
	return 0;
}

static int net_show_filter(struct kretprobe_instance *ri, bool (*match)(u16))
{
	struct net_show_data *d = (struct net_show_data *)ri->data;
	const char *line;
	size_t line_len;

	if (!d->track || !d->m || !d->m->buf)
		return 0;
	if (d->m->count <= d->count_before)
		return 0;
	if (d->m->count > d->m->size)
		return 0;

	line	 = d->m->buf + d->count_before;
	line_len = d->m->count - d->count_before;

	if (line_has_hidden_port(line, line_len, match))
		d->m->count = d->count_before;
	return 0;
}

static int tcp_show_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return net_show_filter(ri, hide_match_tcp_port);
}

static int udp_show_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return net_show_filter(ri, hide_match_udp_port);
}

#define DEFINE_NET_KRETPROBE(_name, _ret)		\
static struct kretprobe _name = {			\
	.handler       = _ret,				\
	.entry_handler = net_show_pre,			\
	.data_size     = sizeof(struct net_show_data),	\
	.maxactive     = 32,				\
}

DEFINE_NET_KRETPROBE(tcp4_kp, tcp_show_ret);
DEFINE_NET_KRETPROBE(tcp6_kp, tcp_show_ret);
DEFINE_NET_KRETPROBE(udp4_kp, udp_show_ret);
DEFINE_NET_KRETPROBE(udp6_kp, udp_show_ret);

static bool tcp4_attached, tcp6_attached, udp4_attached, udp6_attached;

static int hide_net_init(void)
{
	tcp4_kp.kp.symbol_name = "tcp4_seq_show";
	if (register_kretprobe(&tcp4_kp) == 0)
		tcp4_attached = true;

	tcp6_kp.kp.symbol_name = "tcp6_seq_show";
	if (register_kretprobe(&tcp6_kp) == 0)
		tcp6_attached = true;

	udp4_kp.kp.symbol_name = "udp4_seq_show";
	if (register_kretprobe(&udp4_kp) == 0)
		udp4_attached = true;

	udp6_kp.kp.symbol_name = "udp6_seq_show";
	if (register_kretprobe(&udp6_kp) == 0)
		udp6_attached = true;

	pr_info("akane: hide_net: tcp4=%d tcp6=%d udp4=%d udp6=%d\n",
		tcp4_attached, tcp6_attached, udp4_attached, udp6_attached);
	return 0;
}

static void hide_net_exit(void)
{
	if (tcp4_attached)
		unregister_kretprobe(&tcp4_kp);
	if (tcp6_attached)
		unregister_kretprobe(&tcp6_kp);
	if (udp4_attached)
		unregister_kretprobe(&udp4_kp);
	if (udp6_attached)
		unregister_kretprobe(&udp6_kp);
}

/*
 * Memory: hide HIDE_FROM_MEMORY-flagged akane VMAs from non-root
 * introspection, both cross-process and from inside the target.
 */

/* True if any page in [start, start+len) lands in a hidden akane allocation. */
static bool range_hits_hidden(struct mm_struct *mm,
			      unsigned long start, unsigned long len)
{
	unsigned long addr;

	if (!mm || !len)
		return false;
	for (addr = start & PAGE_MASK; addr < start + len; addr += PAGE_SIZE) {
		if (akane_mask_addr_hidden_from_memory(mm, addr))
			return true;
	}
	return false;
}

/*
 * access_remote_vm (arm64: x0=mm, x1=addr, x3=len) backs /proc/<pid>/mem
 * reads. Block by forcing a 0-byte return, which the reader sees as EOF.
 */
struct mem_hide_data {
	bool intercept;
};

static int access_remote_vm_pre(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct mem_hide_data *d = (struct mem_hide_data *)ri->data;
	struct mm_struct *mm = (struct mm_struct *)regs->regs[0];
	unsigned long addr = regs->regs[1];
	int len = (int)regs->regs[3];

	d->intercept = false;
	if (akane_is_root() || len <= 0)
		return 0;
	if (range_hits_hidden(mm, addr, (unsigned long)len))
		d->intercept = true;
	return 0;
}

static int access_remote_vm_ret(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct mem_hide_data *d = (struct mem_hide_data *)ri->data;

	if (d->intercept)
		regs->regs[0] = 0;
	return 0;
}

static struct kretprobe access_remote_vm_kp = {
	.handler       = access_remote_vm_ret,
	.entry_handler = access_remote_vm_pre,
	.data_size     = sizeof(struct mem_hide_data),
	.maxactive     = 32,
};

/*
 * process_vm_readv / process_vm_writev (syscall pt_regs at x0; from it
 * x0=pid, x3=remote iovec, x4=iovcnt). Fail the whole syscall with -EFAULT
 * if any remote_iov entry overlaps a hidden VMA.
 */
struct pvr_hide_data {
	bool intercept;
};

static bool pvr_iovs_hidden(pid_t target_pid,
			    const struct iovec __user *rvec,
			    unsigned long riovcnt)
{
	struct mm_struct *mm;
	struct iovec iov;
	unsigned long i;
	bool hit = false;

	if (!rvec || !riovcnt)
		return false;
	if (riovcnt > UIO_MAXIOV)
		riovcnt = UIO_MAXIOV;

	mm = akane_get_target_mm(target_pid);
	if (!mm)
		return false;

	for (i = 0; i < riovcnt; i++) {
		if (copy_from_user(&iov, &rvec[i], sizeof(iov)))
			break;
		if (range_hits_hidden(mm, (unsigned long)iov.iov_base,
				      iov.iov_len)) {
			hit = true;
			break;
		}
	}
	mmput(mm);
	return hit;
}

static int pvr_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pvr_hide_data *d = (struct pvr_hide_data *)ri->data;
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
	pid_t pid;
	const struct iovec __user *rvec;
	unsigned long riovcnt;

	d->intercept = false;
	if (!user_regs || akane_is_root())
		return 0;

	pid	= (pid_t)user_regs->regs[0];
	rvec	= (const struct iovec __user *)user_regs->regs[3];
	riovcnt = (unsigned long)user_regs->regs[4];

	if (pvr_iovs_hidden(pid, rvec, riovcnt))
		d->intercept = true;
	return 0;
}

static int pvr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pvr_hide_data *d = (struct pvr_hide_data *)ri->data;

	if (d->intercept)
		regs->regs[0] = (unsigned long)(-EFAULT);
	return 0;
}

#define DEFINE_PVR_KRETPROBE(_name)			\
static struct kretprobe _name = {			\
	.handler       = pvr_ret,			\
	.entry_handler = pvr_pre,			\
	.data_size     = sizeof(struct pvr_hide_data),	\
	.maxactive     = 32,				\
}

DEFINE_PVR_KRETPROBE(pvr_readv_kp);
DEFINE_PVR_KRETPROBE(pvr_writev_kp);

/*
 * show_smap (arm64: x0=seq_file, x1=vm_area_struct) emits a /proc/<pid>/smaps
 * stanza. Rewind seq_file->count on return if the VMA is hidden.
 */
struct smap_hide_data {
	struct seq_file *m;
	size_t		 count_before;
	bool		 track;
};

static int show_smap_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct smap_hide_data *d = (struct smap_hide_data *)ri->data;
	struct seq_file *m = (struct seq_file *)regs->regs[0];
	struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];

	d->track = false;
	if (!m || !vma || akane_is_root())
		return 0;
	if (!akane_mask_vma_hidden_from_memory(vma))
		return 0;

	d->m		= m;
	d->count_before = m->count;
	d->track	= true;
	return 0;
}

static int show_smap_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct smap_hide_data *d = (struct smap_hide_data *)ri->data;

	if (!d->track || !d->m || !d->m->buf)
		return 0;
	if (d->m->count > d->count_before && d->m->count <= d->m->size)
		d->m->count = d->count_before;
	return 0;
}

static struct kretprobe show_smap_kp = {
	.handler       = show_smap_ret,
	.entry_handler = show_smap_pre,
	.data_size     = sizeof(struct smap_hide_data),
	.maxactive     = 32,
};

/*
 * pagemap_read (arm64: x0=file, x2=count, x3=ppos). Each PTE is 8 bytes at
 * file offset (vaddr/PAGE_SIZE)*8, so we recover the VA range from (*ppos,
 * count); file->private_data is the target's mm. Hidden page -> return 0.
 */
struct pagemap_hide_data {
	bool intercept;
};

static int pagemap_read_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pagemap_hide_data *d = (struct pagemap_hide_data *)ri->data;
	struct file *file = (struct file *)regs->regs[0];
	size_t count = (size_t)regs->regs[2];
	loff_t __user *uppos = (loff_t __user *)regs->regs[3];
	loff_t pos = 0;
	unsigned long start, len;
	struct mm_struct *mm;

	d->intercept = false;
	if (!file || !uppos || !count || akane_is_root())
		return 0;

	if (copy_from_user(&pos, uppos, sizeof(pos)))
		return 0;
	if (pos < 0)
		return 0;

	start = ((unsigned long)pos / 8) << PAGE_SHIFT;
	len   = (count / 8) << PAGE_SHIFT;
	if (!len)
		return 0;

	mm = (struct mm_struct *)file->private_data;
	if (range_hits_hidden(mm, start, len))
		d->intercept = true;
	return 0;
}

static int pagemap_read_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct pagemap_hide_data *d = (struct pagemap_hide_data *)ri->data;

	if (d->intercept)
		regs->regs[0] = 0;
	return 0;
}

static struct kretprobe pagemap_read_kp = {
	.handler       = pagemap_read_ret,
	.entry_handler = pagemap_read_pre,
	.data_size     = sizeof(struct pagemap_hide_data),
	.maxactive     = 32,
};

/*
 * mincore (arm64 syscall regs: x0=start, x1=len). -ENOMEM for a range over a
 * hidden VMA is the normal "not mapped" response, so it's indistinguishable.
 */
struct mincore_hide_data {
	bool intercept;
};

static int mincore_pre(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mincore_hide_data *d = (struct mincore_hide_data *)ri->data;
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
	unsigned long start, len;

	d->intercept = false;
	if (!user_regs || akane_is_root())
		return 0;

	start = user_regs->regs[0];
	len   = user_regs->regs[1];
	if (range_hits_hidden(current->mm, start, len))
		d->intercept = true;
	return 0;
}

static int mincore_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct mincore_hide_data *d = (struct mincore_hide_data *)ri->data;

	if (d->intercept)
		regs->regs[0] = (unsigned long)(-ENOMEM);
	return 0;
}

static struct kretprobe mincore_kp = {
	.handler       = mincore_ret,
	.entry_handler = mincore_pre,
	.data_size     = sizeof(struct mincore_hide_data),
	.maxactive     = 32,
};

static bool access_attached, readv_attached, writev_attached;
static bool smap_attached, pagemap_attached, mincore_attached;

static int hide_memory_init(void)
{
	access_remote_vm_kp.kp.symbol_name = "access_remote_vm";
	if (register_kretprobe(&access_remote_vm_kp) == 0)
		access_attached = true;

	pvr_readv_kp.kp.symbol_name = "__arm64_sys_process_vm_readv";
	if (register_kretprobe(&pvr_readv_kp) == 0)
		readv_attached = true;

	pvr_writev_kp.kp.symbol_name = "__arm64_sys_process_vm_writev";
	if (register_kretprobe(&pvr_writev_kp) == 0)
		writev_attached = true;

	/* show_smap may be inlined; fall back to show_smap_vma. */
	show_smap_kp.kp.symbol_name = "show_smap";
	if (register_kretprobe(&show_smap_kp) != 0) {
		show_smap_kp.kp.symbol_name = "show_smap_vma";
		if (register_kretprobe(&show_smap_kp) == 0)
			smap_attached = true;
	} else {
		smap_attached = true;
	}

	pagemap_read_kp.kp.symbol_name = "pagemap_read";
	if (register_kretprobe(&pagemap_read_kp) == 0)
		pagemap_attached = true;

	mincore_kp.kp.symbol_name = "__arm64_sys_mincore";
	if (register_kretprobe(&mincore_kp) == 0)
		mincore_attached = true;

	pr_info("akane: hide_memory: remote_vm=%d readv=%d writev=%d smap=%d pagemap=%d mincore=%d\n",
		access_attached, readv_attached, writev_attached,
		smap_attached, pagemap_attached, mincore_attached);
	return 0;
}

static void hide_memory_exit(void)
{
	if (access_attached)
		unregister_kretprobe(&access_remote_vm_kp);
	if (readv_attached)
		unregister_kretprobe(&pvr_readv_kp);
	if (writev_attached)
		unregister_kretprobe(&pvr_writev_kp);
	if (smap_attached)
		unregister_kretprobe(&show_smap_kp);
	if (pagemap_attached)
		unregister_kretprobe(&pagemap_read_kp);
	if (mincore_attached)
		unregister_kretprobe(&mincore_kp);
}

/* Registry comes up first (it seeds the defaults the hooks consult). */
int akane_hide_init(void)
{
	int ret = hide_registry_init();

	if (ret) {
		pr_err("akane: hide: registry init failed: %d\n", ret);
		return ret;
	}

	hide_files_init();
	hide_modules_init();
	hide_net_init();
	hide_memory_init();
	return 0;
}

void akane_hide_exit(void)
{
	hide_memory_exit();
	hide_net_exit();
	hide_modules_exit();
	hide_files_exit();
	hide_registry_exit();
}
