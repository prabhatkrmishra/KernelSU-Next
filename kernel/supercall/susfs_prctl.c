#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/susfs.h>

#include "uapi/supercall.h"

extern int ksu_handle_susfs_prctl_cmd(struct ksu_susfs_cmd *cmd);

static inline bool is_susfs_cmd(unsigned long cmd)
{
	switch (cmd) {
	case CMD_SUSFS_ADD_SUS_PATH:
	case CMD_SUSFS_ADD_SUS_MOUNT:
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
	case CMD_SUSFS_ADD_TRY_UMOUNT:
	case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS:
	case CMD_SUSFS_SET_UNAME:
	case CMD_SUSFS_ENABLE_LOG:
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
	case CMD_SUSFS_SUS_SU:
	case CMD_SUSFS_SHOW_VERSION:
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
	case CMD_SUSFS_SHOW_VARIANT:
	case CMD_SUSFS_IS_SUS_SU_READY:
	case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE:
		return true;
	default:
		return false;
	}
}

int ksu_handle_susfs_prctl(int option, unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5)
{
	struct ksu_susfs_cmd cmd;

	if (current_uid().val != 0)
		return -ENOSYS;

	if (!is_susfs_cmd(arg2))
		return -ENOSYS;

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = arg2;
	cmd.buf = arg3;
	cmd.ret = arg5;

	return ksu_handle_susfs_prctl_cmd(&cmd);
}
