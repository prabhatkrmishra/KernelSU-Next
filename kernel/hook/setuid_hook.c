#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/hook_manager.h"
#include "feature/kernel_umount.h"
#include "compat/kernel_compat.h"

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
extern u32 susfs_zygote_sid;
extern bool susfs_is_sid_equal(void *sec, u32 sid2);
extern bool susfs_is_umount_for_zygote_system_process_enabled;
#endif

int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    {
        const struct cred *old_cred = get_current_cred();
        bool is_zygote_child = old_cred && susfs_is_sid_equal(old_cred->security, susfs_zygote_sid);
        put_cred(old_cred);
        if (likely(is_zygote_child) && unlikely(new_uid < 10000 && new_uid >= 1000)) {
            if (susfs_is_umount_for_zygote_system_process_enabled) {
                goto out_ksu_handle_umount;
            }
        }
    }
#endif

    if (unlikely(is_uid_manager(new_uid))) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp();
#endif

#ifdef KSU_KPROBES_HOOK
        ksu_set_task_tracepoint_flag(current);
#endif

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        if (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
        }
#else
		disable_seccomp();
#endif

#ifdef KSU_KPROBES_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
	} else {
#ifdef KSU_KPROBES_HOOK
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
#ifdef CONFIG_KSU_SUSFS
		if (is_appuid(new_uid)) {
			task_lock(current);
			current->susfs_task_state |= TASK_STRUCT_NON_ROOT_USER_APP_PROC;
			task_unlock(current);
		}
#endif
    }

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
out_ksu_handle_umount:
#endif
    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}

void __init ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
	pr_info("ksu_core_exit\n");
	ksu_kernel_umount_exit();
}