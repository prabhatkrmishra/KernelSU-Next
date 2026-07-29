#include <linux/fs.h>
#include <linux/atomic.h>
#include <linux/jump_label.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#include <asm/set_memory.h>
#else
#include <asm/cacheflush.h>
#endif
#include <linux/namei.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include "policy/feature.h"
#include "include/ksu.h"
#include  "uapi/feature.h"
#include "selinux/selinux.h"
#include "feature/selinux_hide.h"

#include "ss/services.h"
#include "ss/sidtab.h"
#include "avc.h"
#include "flask.h"
#include "av_permissions.h"

#if defined(CONFIG_KSU_KPROBES_HOOK)
extern struct kprobe *init_kprobe(const char *name, int (*pre_handler)(struct kprobe *, struct pt_regs *));
extern void destroy_kprobe(struct kprobe **kp_ptr);
extern int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs);
static struct kprobe *selinux_hide_slow_avc_audit_kp;
#endif

static struct page *fake_status = NULL;
static DEFINE_MUTEX(fake_status_init_mutex);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
extern bool ksu_input_hook __read_mostly __attribute__((weak));
#else
extern bool ksu_input_hook __read_mostly;
#endif
extern struct selinux_state selinux_state;

extern unsigned long kallsyms_lookup_name(const char *name);

// enabled by default
static bool ksu_selinux_hide_is_enabled __read_mostly = true;

static u32 ksu_sid __read_mostly = 0;
static u32 priv_app_sid __read_mostly = 0;

static int ksu_selinux_get_sids(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	int err1 = security_context_to_sid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid, GFP_KERNEL);
    int err2 = security_context_to_sid("u:r:priv_app:s0:c512,c768", 
                                       strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid, GFP_KERNEL);
#else
	int err1 = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
	int err2 = security_secctx_to_secid("u:r:priv_app:s0:c512,c768",
					     strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
#endif
	if (!err1) pr_info("ksu_selinux_hide: ksu_sid=%u\n", ksu_sid);
	if (!err2) pr_info("ksu_selinux_hide: priv_app_sid=%u\n", priv_app_sid);
	return (!ksu_sid || !priv_app_sid) ? -1 : 0;
}

static void initialize_fake_status(void)
{
	if (READ_ONCE(fake_status))
		return;

	mutex_lock(&fake_status_init_mutex);
	if (fake_status) /* double-check after lock */
		goto out;

#ifdef KSU_COMPAT_USE_SELINUX_STATE
	struct page *real_page = selinux_kernel_status_page(&selinux_state);
#else
	struct page *real_page = selinux_kernel_status_page();
#endif
	if (!real_page) {
		pr_warn("ksu_selinux_hide: status_page not exists\n");
		goto out;
	}

	struct selinux_kernel_status *status = page_address(real_page);
	if (!status->enforcing && !ksu_late_loaded) {
		pr_warn("ksu_selinux_hide: skip not enforcing\n");
		goto out;
	}

	struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!new_page) {
		pr_err("ksu_selinux_hide: failed to allocate fake status page\n");
		goto out;
	}

	struct selinux_kernel_status *new_status = page_address(new_page);
	memcpy(new_status, status, sizeof(*status));
	if (ksu_late_loaded && !new_status->enforcing) {
		/*
		 * In late_load mode we may be loaded after setenforce 0.
		 * Adjust sequence to look like a normal enforcing boot.
		 * Assumes setenforce 0 was called exactly once.
		 */
		new_status->enforcing = 1;
		new_status->sequence = 4;
	}
	
	WRITE_ONCE(fake_status, new_page);
	pr_info("ksu_selinux_hide: fake status ready: sequence=%d policyload=%d enforcing=%d\n",
		new_status->sequence, new_status->policyload,
		new_status->enforcing);
out:
	mutex_unlock(&fake_status_init_mutex);
}

typedef int (*sel_open_handle_status_fn)(struct inode *inode,
					 struct file *filp);
static sel_open_handle_status_fn orig_sel_open_handle_status = NULL;

static int __nocfi my_sel_open_handle_status(struct inode *inode, struct file *filp)
{
	sel_open_handle_status_fn orig = READ_ONCE(orig_sel_open_handle_status);
	if (likely(test_thread_flag(TIF_SECCOMP) &&
	current_uid().val >= 10000 &&
		   ksu_selinux_hide_is_enabled)) {
		struct page *data = READ_ONCE(fake_status);
		if (data) {
			filp->private_data = page_address(data);
			return 0;
		}
	}

	if (unlikely(!orig))
		return -EINVAL;

	return orig(inode, filp);
}

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

/*
 * Patch a pointer-sized slot that lives in read-only memory (rodata arrays
 * like selinuxfs write_op[], or __lsm_ro_after_init hook heads) by mapping
 * the backing page(s) writable.
 */
static int patch_text_pointer(void **slot, void *value)
{
	unsigned long addr = (unsigned long)slot;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK;

	struct page *pages[2];
	int npages = 1;
	if (offset + sizeof(void *) > PAGE_SIZE)
		npages = 2;

	pages[0] = phys_to_page(__pa(base));
	if (!pages[0])
		return -EFAULT;
	if (npages == 2) {
		pages[1] = phys_to_page(__pa(base + PAGE_SIZE));
		if (!pages[1])
			return -EFAULT;
	}

	void *writable_addr = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return -ENOMEM;

	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();
	FORCE_VOLATILE(*target_slot) = value;
	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);
	smp_mb();
	return 0;
}

static int patch_fops_open(struct file_operations *ops,
			    sel_open_handle_status_fn new_open)
{
	return patch_text_pointer((void **)&ops->open, (void *)new_open);
}

static int resolve_fops(const char *path_str, struct file_operations **out_fops)
{
	struct path path;
	int error = kern_path(path_str, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_err("ksu_selinux_hide: kern_path(%s) failed: %d\n", path_str, error);
		return error;
	}
	
	int ret = -ENOENT;
	if (!path.dentry || !d_inode(path.dentry))
		goto out;
	
	*out_fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!*out_fops)
		goto out;

	ret = 0;
out:
	path_put(&path);
	return ret;
}

static void hook_selinux_status_open(void)
{
	if (orig_sel_open_handle_status)
	return;

	struct file_operations *ops = NULL;
	if (resolve_fops("/sys/fs/selinux/status", &ops)) {
		pr_err("ksu_selinux_hide: sel_handle_status_ops not found, fake status disabled\n");
		return;
	}

	if (!ops->open) {
		pr_err("ksu_selinux_hide: sel_handle_status_ops->open is NULL\n");
		return;
	}
	
	orig_sel_open_handle_status = ops->open;
	patch_fops_open(ops, my_sel_open_handle_status);
	pr_info("ksu_selinux_hide: hooked sel_handle_status_ops->open\n");
}

static void unhook_selinux_status_open(void)
{
	if (!orig_sel_open_handle_status)
	return;

	struct file_operations *ops = NULL;
	if (resolve_fops("/sys/fs/selinux/status", &ops)) {
		pr_err("ksu_selinux_hide: sel_handle_status_ops not found on unhook\n");
		return;
}

	patch_fops_open(ops, orig_sel_open_handle_status);
	orig_sel_open_handle_status = NULL;
	pr_info("ksu_selinux_hide: unhooked sel_handle_status_ops->open\n");
}

// =====================================================================
// write_op[] (context/access) spoofing against a pristine policy backup
// =====================================================================

/*
 * The live policy is mutated in place by KSU, so answering app queries
 * against it would leak KSU rules.  answer them against a snapshot of the
 * pristine policy instead.
 */
static struct selinux_state fake_state;
static struct selinux_ss fake_ss;

/*
 * Spoof query handlers read fake_state, which aliases the backup
 * policy's storage; disable() drains this counter after unhooking so
 * the backup can never be freed under an in-flight query.
 */
static atomic_t hide_query_inflight = ATOMIC_INIT(0);

static int init_fake_state(void)
{
	struct selinux_state *real = &selinux_state;
	struct policydb *backup_db;
	struct sidtab *backup_sidtab;

	if (!real->ss || !real->initialized)
		return -EAGAIN;

	backup_db = ksu_get_backup_policydb();
	backup_sidtab = ksu_get_backup_sidtab();
	if (!backup_db || !backup_sidtab) {
		pr_warn("ksu_selinux_hide: no backup policy available yet\n");
		return -EAGAIN;
	}

	memset(&fake_state, 0, sizeof(fake_state));
	memset(&fake_ss, 0, sizeof(fake_ss));
	fake_state.initialized = true;
	fake_state.ss = &fake_ss;
	fake_ss.policydb = *backup_db;
	fake_ss.sidtab = backup_sidtab;
	rwlock_init(&fake_ss.policy_rwlock);
	fake_ss.latest_granting = real->ss->latest_granting;
	fake_ss.map = real->ss->map;
	return 0;
}

typedef ssize_t (*write_op_fn)(struct file *, char *, size_t);

enum sel_inos {
	SEL_ROOT_INO = 2,
	SEL_LOAD, /* load policy */
	SEL_ENFORCE, /* get or set enforcing status */
	SEL_CONTEXT, /* validate context */
	SEL_ACCESS, /* compute access decision */
};

static write_op_fn *selinux_write_op;
static write_op_fn *context_write, *access_write;
static write_op_fn orig_context_write, orig_access_write;

static ssize_t __nocfi my_write_context(struct file *file, char *buf, size_t size)
{
	// apply to all app uids
	write_op_fn orig = READ_ONCE(orig_context_write);
	if (likely(current_uid().val < 10000)) {
		if (unlikely(!orig))
			return -EINVAL;
		return orig(file, buf, size);
	}
	char *canon = NULL;
	u32 sid, len;
	ssize_t length;

	atomic_inc(&hide_query_inflight);
	length = avc_has_perm(&selinux_state, current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__CHECK_CONTEXT, NULL);
	if (length)
		goto out;

	length = security_context_to_sid(&fake_state, buf, size, &sid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_sid_to_context(&fake_state, sid, &canon, &len);
	if (length)
		goto out;

	length = -ERANGE;
	if (len > SIMPLE_TRANSACTION_LIMIT) {
		pr_err("SELinux: %s:  context size (%u) exceeds "
		       "payload max\n", __func__, len);
		goto out;
	}

	memcpy(buf, canon, len);
	length = len;
out:
	atomic_dec(&hide_query_inflight);
	kfree(canon);
	return length;
}

static ssize_t __nocfi my_write_access(struct file *file, char *buf, size_t size)
{
	// apply to all app uids
	write_op_fn orig = READ_ONCE(orig_access_write);
	if (likely(current_uid().val < 10000)) {
		if (unlikely(!orig))
			return -EINVAL;
		return orig(file, buf, size);
	}
	char *scon = NULL, *tcon = NULL;
	u32 ssid, tsid;
	u16 tclass;
	struct av_decision avd;
	ssize_t length;

	atomic_inc(&hide_query_inflight);
	length = avc_has_perm(&selinux_state, current_sid(), SECINITSID_SECURITY,
			      SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
	if (length)
		goto out;

	length = -ENOMEM;
	scon = kzalloc(size + 1, GFP_KERNEL);
	if (!scon)
		goto out;

	length = -ENOMEM;
	tcon = kzalloc(size + 1, GFP_KERNEL);
	if (!tcon)
		goto out;

	length = -EINVAL;
	if (sscanf(buf, "%s %s %hu", scon, tcon, &tclass) != 3)
		goto out;

	length = security_context_str_to_sid(&fake_state, scon, &ssid, GFP_KERNEL);
	if (length)
		goto out;

	length = security_context_str_to_sid(&fake_state, tcon, &tsid, GFP_KERNEL);
	if (length)
		goto out;

	security_compute_av_user(&fake_state, ssid, tsid, tclass, &avd);

	length = scnprintf(buf, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x",
			   avd.allowed, 0xffffffff, avd.auditallow, avd.auditdeny,
			   avd.seqno, avd.flags);
out:
	atomic_dec(&hide_query_inflight);
	kfree(tcon);
	kfree(scon);
	return length;
}

// =====================================================================
// setprocattr spoofing: swap selinux's own LSM hook slot
// =====================================================================

typedef int (*setprocattr_fn)(const char *name, void *value, size_t size);
static setprocattr_fn orig_setprocattr_fn;
static struct security_hook_list *selinux_setprocattr_hook;

static int __nocfi my_setprocattr(const char *name, void *value, size_t size)
{
	setprocattr_fn orig = READ_ONCE(orig_setprocattr_fn);
	int error;
	u32 mysid, sid;
	char *str = value;

	if (unlikely(!orig))
		return -EINVAL;

	if (likely(current_uid().val < 10000)) {
		goto call_orig;
	}

	if (strcmp(name, "current")) {
		goto call_orig;
	}
	mysid = current_sid();

	error = avc_has_perm(&selinux_state, mysid, mysid, SECCLASS_PROCESS,
			     PROCESS__SETCURRENT, NULL);
	if (error) {
		return error;
	}

	if (size && str[0] && str[0] != '\n') {
		if (str[size - 1] == '\n') {
			str[size - 1] = 0;
			size--;
		}
		atomic_inc(&hide_query_inflight);
		error = security_context_to_sid(&fake_state, str, size, &sid,
						GFP_KERNEL);
		atomic_dec(&hide_query_inflight);
		if (error) {
			return error;
		}
	}

call_orig:
	return orig(name, value, size);
}

static int hook_selinux_setprocattr(void)
{
	struct security_hook_list *hp;

	if (orig_setprocattr_fn)
		return 0;

	hlist_for_each_entry(hp, &security_hook_heads.setprocattr, list) {
		if (hp->lsm && strcmp(hp->lsm, "selinux") == 0) {
			selinux_setprocattr_hook = hp;
			orig_setprocattr_fn = hp->hook.setprocattr;
			return patch_text_pointer(
				(void **)&selinux_setprocattr_hook->hook.setprocattr,
				(void *)my_setprocattr);
		}
	}

	return -ENOENT;
}

static void unhook_selinux_setprocattr(void)
{
	if (!orig_setprocattr_fn)
		return;

	patch_text_pointer((void **)&selinux_setprocattr_hook->hook.setprocattr,
			   (void *)orig_setprocattr_fn);
	orig_setprocattr_fn = NULL;
	selinux_setprocattr_hook = NULL;
}

// =====================================================================
// enable/disable
// =====================================================================

static DEFINE_MUTEX(selinux_hide_mutex);
static bool ksu_selinux_hide_running __read_mostly = false;

static void ksu_selinux_hide_unhook(void);

static int ksu_selinux_hide_enable(void)
{
	int ret;

	mutex_lock(&selinux_hide_mutex);
	if (ksu_selinux_hide_running || !ksu_selinux_hide_is_enabled) {
		ret = 0;
		goto out;
	}

	if (ksu_selinux_get_sids())
		pr_warn("ksu_selinux_hide: sid grab failed\n");

	ret = init_fake_state();
	if (ret)
		goto out;

	selinux_write_op = (write_op_fn *)kallsyms_lookup_name("write_op");
	if (!selinux_write_op) {
		pr_err("ksu_selinux_hide: no write_op found!\n");
		ret = -ENOSYS;
		goto out;
	}

	hook_selinux_status_open();

	context_write = &selinux_write_op[SEL_CONTEXT];
	pr_info("ksu_selinux_hide: context_write: 0x%lx [%pSb]\n",
		(unsigned long)*context_write, *context_write);
	write_op_fn my = my_write_context;
	orig_context_write = *context_write;
	ret = patch_text_pointer((void **)context_write, (void *)my);
	if (ret) {
		pr_err("ksu_selinux_hide: patch_text context_write err: %d\n", ret);
		goto unhook;
	}

	access_write = &selinux_write_op[SEL_ACCESS];
	pr_info("ksu_selinux_hide: access_write: 0x%lx [%pSb]\n",
		(unsigned long)*access_write, *access_write);
	my = my_write_access;
	orig_access_write = *access_write;
	ret = patch_text_pointer((void **)access_write, (void *)my);
	if (ret) {
		pr_err("ksu_selinux_hide: patch_text access_write err: %d\n", ret);
		goto unhook;
	}

	ret = hook_selinux_setprocattr();
	if (ret) {
		pr_err("ksu_selinux_hide: hook setprocattr err: %d\n", ret);
		goto unhook;
	}

#if defined(CONFIG_KSU_KPROBES_HOOK)
	selinux_hide_slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
#endif

	ksu_selinux_hide_running = true;
	ret = 0;
	goto out;

unhook:
	ksu_selinux_hide_unhook();
	ret = -ENOSYS;
out:
	mutex_unlock(&selinux_hide_mutex);
	return ret;
}

static void ksu_selinux_hide_unhook(void)
{
	int ret;

	if (orig_context_write) {
		ret = patch_text_pointer((void **)context_write, (void *)orig_context_write);
		orig_context_write = NULL;
		if (ret)
			pr_err("ksu_selinux_hide: exit: patch_text context_write err: %d\n", ret);
	}
	if (orig_access_write) {
		ret = patch_text_pointer((void **)access_write, (void *)orig_access_write);
		orig_access_write = NULL;
		if (ret)
			pr_err("ksu_selinux_hide: exit: patch_text access_write err: %d\n", ret);
	}
	unhook_selinux_status_open();
	unhook_selinux_setprocattr();
}

static void ksu_selinux_hide_disable(void)
{
	mutex_lock(&selinux_hide_mutex);
	if (!ksu_selinux_hide_running) {
		mutex_unlock(&selinux_hide_mutex);
		return;
	}

	ksu_selinux_hide_unhook();
#if defined(CONFIG_KSU_KPROBES_HOOK)
	destroy_kprobe(&selinux_hide_slow_avc_audit_kp);
#endif
	ksu_selinux_hide_running = false;

	/*
	 * Let in-flight spoof queries finish before returning: once we
	 * drop the mutex, the pristine backup may be freed (see
	 * ksu_selinux_hide_drop_backup_if_unused()), and those queries
	 * read fake_state which aliases it.
	 */
	while (atomic_read(&hide_query_inflight))
		usleep_range(50, 100);

	mutex_unlock(&selinux_hide_mutex);
}

// =====================================================================
// feature handler
// =====================================================================

static int selinux_hide_status_feature_get(u64 *value)
{
	*value = ksu_selinux_hide_is_enabled ? 1 : 0;
	return 0;
}

static int selinux_hide_status_feature_set(u64 value)
{
	bool enable = !!value;
	int ret = 0;

	if (enable == ksu_selinux_hide_is_enabled) {
		pr_info("ksu_selinux_hide: no need to change\n");
		return 0;
	}
	ksu_selinux_hide_is_enabled = enable;

	if (!enable)
		ksu_selinux_hide_disable();
	else
		ret = ksu_selinux_hide_enable();

	if (ret)
		pr_warn("ksu_selinux_hide: set to %d failed: %d\n", enable, ret);
	else
		pr_info("ksu_selinux_hide: set to %d\n", enable);
	return ret;
}

static const struct ksu_feature_handler selinux_hide_status_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE_STATUS,
	.name = "selinux_hide_status",
	.get_handler = selinux_hide_status_feature_get,
	.set_handler = selinux_hide_status_feature_set,
};

static int ksu_hide_init_thread(void *data)
{
	set_user_nice(current, 19);

	while (READ_ONCE(ksu_input_hook))
		msleep(5000);

	if (ksu_selinux_hide_is_enabled) {
		int tries = 0;
		while (ksu_selinux_hide_enable()) {
			if (++tries > 10) {
				pr_warn("ksu_selinux_hide: giving up on enable after %d tries\n", tries);
				break;
			}
			msleep(1000);
		}
	}

	int tries = 0;
try_again:
	initialize_fake_status();
	if (READ_ONCE(fake_status))
		goto page_ok;

	msleep(1000);
	if (++tries > 10) {
		pr_warn("ksu_selinux_hide: giving up on fake status page after %d tries\n", tries);
		return 0;
	}
	goto try_again;

page_ok:
	hook_selinux_status_open();
	return 0;
}

void __init ksu_selinux_hide_init(void)
{
	if (ksu_register_feature_handler(&selinux_hide_status_handler))
		pr_err("ksu_selinux_hide: failed to register feature handler\n");

	kthread_run(ksu_hide_init_thread, NULL, "ksu_selinux_hide_init");
}

void __exit ksu_selinux_hide_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE_STATUS);
	ksu_selinux_hide_disable();
	mutex_lock(&fake_status_init_mutex);
	if (fake_status) {
		__free_page(fake_status);
		fake_status = NULL;
	}
	mutex_unlock(&fake_status_init_mutex);
}

void ksu_selinux_hide_drop_backup_if_unused(void)
{
	bool drop = false;

	/*
	 * Hold the hide mutex across both the check and the drop: it
	 * excludes ksu_selinux_hide_enable(), whose fake_state aliases
	 * the backup storage, and disable() has already drained any
	 * in-flight spoof queries by the time running goes false.
	 */
	mutex_lock(&selinux_hide_mutex);
	if (!ksu_selinux_hide_is_enabled && !ksu_selinux_hide_running)
		drop = true;
	if (drop)
		ksu_drop_backup_policy();
	mutex_unlock(&selinux_hide_mutex);
}
