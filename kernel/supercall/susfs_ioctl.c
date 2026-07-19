#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/susfs.h>

#include "uapi/supercall.h"
#include "compat/kernel_compat.h"
#include "klog.h"

static void write_ret_to_user(struct ksu_susfs_cmd *cmd, int val)
{
	if (cmd->ret) {
		if (copy_to_user((void __user *)cmd->ret, &val, sizeof(val)))
			pr_info("susfs: copy_to_user() failed\n");
	}
}

/* Core handler - takes a kernel-space ksu_susfs_cmd pointer */
static int __ksu_handle_susfs_cmd(struct ksu_susfs_cmd *cmd)
{
	int error = 0;

	switch (cmd->cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_sus_path))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", error);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_ADD_SUS_MOUNT: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_sus_mount))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", error);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", error);
		break;
	}
	case CMD_SUSFS_UPDATE_SUS_KSTAT: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", error);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	case CMD_SUSFS_ADD_TRY_UMOUNT: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_try_umount))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", error);
		break;
	}
	case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS: {
		extern void susfs_run_try_umount_for_current_mnt_ns(void);
		susfs_run_try_umount_for_current_mnt_ns();
		pr_info("susfs: CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS\n");
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_uname))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_set_uname((struct st_susfs_uname __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", error);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG: {
		u64 value;
		if (!cmd->buf || copy_from_user(&value, (void __user *)cmd->buf, sizeof(value))) {
			error = -EFAULT;
			break;
		}
		if (value != 0 && value != 1) {
			pr_err("susfs: CMD_SUSFS_ENABLE_LOG -> arg3 can only be 0 or 1\n");
			error = -EINVAL;
			break;
		}
		susfs_set_log(value);
		pr_info("susfs: CMD_SUSFS_ENABLE_LOG -> %llu\n", value);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_set_cmdline_or_bootconfig((char __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", error);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_susfs_open_redirect))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", error);
		break;
	}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
	case CMD_SUSFS_SUS_SU: {
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf,
				  sizeof(struct st_sus_su))) {
			pr_err("susfs: CMD_SUSFS_SUS_SU -> buf not accessible\n");
			error = -EFAULT;
			break;
		}
		error = susfs_sus_su((struct st_sus_su __user *)cmd->buf);
		pr_info("susfs: CMD_SUSFS_SUS_SU -> ret: %d\n", error);
		break;
	}
	case CMD_SUSFS_IS_SUS_SU_READY: {
		extern bool susfs_is_sus_su_ready;
		if (!cmd->buf || copy_to_user((void __user *)cmd->buf, &susfs_is_sus_su_ready,
				 sizeof(susfs_is_sus_su_ready))) {
			error = -EFAULT;
		}
		break;
	}
	case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE: {
		int working_mode = susfs_get_sus_su_working_mode();
		if (!cmd->buf || copy_to_user((void __user *)cmd->buf, &working_mode,
				 sizeof(working_mode))) {
			error = -EFAULT;
		}
		break;
	}
#endif
	case CMD_SUSFS_SHOW_VERSION: {
		int len = strlen(SUSFS_VERSION) + 1;
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf, len)) {
			error = -EFAULT;
			break;
		}
		error = copy_to_user((void __user *)cmd->buf, SUSFS_VERSION, len);
		pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", error);
		break;
	}
	case CMD_SUSFS_SHOW_ENABLED_FEATURES: {
		u64 enabled_features = 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1 << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1 << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1 << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1 << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1 << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1 << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
		enabled_features |= (1 << 13);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1 << 14);
#endif
		if (!cmd->buf || copy_to_user((void __user *)cmd->buf, &enabled_features,
				 sizeof(enabled_features))) {
			error = -EFAULT;
		}
		break;
	}
	case CMD_SUSFS_SHOW_VARIANT: {
		int len = strlen(SUSFS_VARIANT) + 1;
		if (!cmd->buf || !ksu_access_ok((void __user *)cmd->buf, len)) {
			error = -EFAULT;
			break;
		}
		error = copy_to_user((void __user *)cmd->buf, SUSFS_VARIANT, len);
		pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", error);
		break;
	}
	default:
		pr_warn("susfs: unknown command %llu\n", cmd->cmd);
		error = -1;
		break;
	}

	/* Always write back error code to userspace */
	write_ret_to_user(cmd, error);

	return 0;
}

/* IOCTL entry point - copies cmd from userspace, then dispatches */
int ksu_handle_susfs_ioctl(void __user *arg)
{
	struct ksu_susfs_cmd cmd;

	if (!arg)
		return -EINVAL;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (current_uid().val != 0)
		return -EPERM;

	return __ksu_handle_susfs_cmd(&cmd);
}

/* Prctl entry point - takes a kernel-space ksu_susfs_cmd built by prctl bridge */
int ksu_handle_susfs_prctl_cmd(struct ksu_susfs_cmd *cmd)
{
	return __ksu_handle_susfs_cmd(cmd);
}
