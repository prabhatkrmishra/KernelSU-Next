#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <asm/ptrace.h>

long ksu_adb_root_handle_execve(struct pt_regs *regs);
long ksu_adb_root_handle_execveat(struct pt_regs *regs);

/* Manual-hook path: no struct pt_regs, env rewrite driven by the caller. */
long ksu_handle_execveat_adb_root(const char *filename,
                                  unsigned long *envp_slot, unsigned long sp);

void ksu_adb_root_init(void);

void ksu_adb_root_exit(void);

#endif