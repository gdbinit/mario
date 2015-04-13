/*
 * <-. (`-')   (`-')  _    (`-')   _
 *    \(OO )_  (OO ).-/ <-.(OO )  (_)         .->
 * ,--./  ,-.) / ,---.  ,------,) ,-(`-')(`-')----.
 * |   `.'   | | \ /`.\ |   /`. ' | ( OO)( OO).-.  '
 * |  |'.'|  | '-'|_.' ||  |_.' | |  |  )( _) | |  |
 * |  |   |  |(|  .-.  ||  .   .'(|  |_/  \|  |)|  |
 * |  |   |  | |  | |  ||  |\  \  |  |'->  '  '-'  '
 * `--'   `--' `--' `--'`--' '--' `--'      `-----'
 *
 * Mario - The kernel component to fix rootpipe
 *
 * This is a TrustedBSD kernel driver to inject a dynamic library
 * or a __RESTRICT segment into specific processes
 *
 * Copyright (c) fG!, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * main.c
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/kernel.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <libkern/libkern.h>
#include <kern/task.h>
#include <sys/proc.h>
#include <sys/vm.h>

#include "config.h"
#include "logging.h"
#include "kernel_symbols.h"
#include "library_injector.h"
#include "uthash.h"

#define VERSION "0.1"

/* global variables */
struct kernel_info g_kinfo; /* structure to hold info for solving kernel symbols */
uint32_t g_initialized;

/* binaries that we want injected with the patching library
 * full path to the binary is required!
 */
char *g_patch_injection_list[] =
{
    "/System/Library/PrivateFrameworks/SystemAdministration.framework/XPCServices/writeconfig.xpc/Contents/MacOS/writeconfig", /* location of vulnerable binary in OS X */
    NULL
};

/* binaries that we want to inject __RESTRICT segment
 * this list was retrieved from 10.10.3 update from all binaries that use the new com.apple.private.admin.writeconfig entitlement
 * removed the binaries that do not exist in Mavericks
 * might be incomplete for binaries that exist in Mavericks but not in Yosemite
 */
char *g_restrict_injection_list[] =
{
    "/System/Library/CoreServices/CoreLocationAgent.app/Contents/MacOS/CoreLocationAgent",
    "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
    "/System/Library/CoreServices/ManagedClient.app/Contents/MacOS/ManagedClient",
    "/System/Library/CoreServices/Setup Assistant.app/Contents/MacOS/Setup Assistant",
    "/System/Library/PreferencePanes/Accounts.prefPane/Contents/XPCServices/com.apple.preferences.users.remoteservice.xpc/Contents/MacOS/com.apple.preferences.users.remoteservice",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/MacOS/DateAndTime",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/DateTime.prefPane/Contents/MacOS/DateTime",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/MacOS/TimeZone",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/Resources/AppleModemSettingTool",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/Resources/TimeZoneAdminTool",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/Resources/TimeZone.prefPane/Contents/Resources/zset",
    "/System/Library/PreferencePanes/DateAndTime.prefPane/Contents/XPCServices/com.apple.preference.datetime.remoteservice.xpc/Contents/MacOS/com.apple.preference.datetime.remoteservice",
    "/System/Library/PreferencePanes/DesktopScreenEffectsPref.prefPane/Contents/Resources/ScreenEffects.prefPane/Contents/MacOS/ScreenEffects",
    "/System/Library/PreferencePanes/iCloudPref.prefPane/Contents/XPCServices/com.apple.preferences.icloud.remoteservice.xpc/Contents/MacOS/com.apple.preferences.icloud.remoteservice",
    "/System/Library/PreferencePanes/InternetAccounts.prefPane/Contents/XPCServices/com.apple.preferences.internetaccounts.remoteservice.xpc/Contents/MacOS/com.apple.preferences.internetaccounts.remoteservice",
    "/System/Library/PreferencePanes/Network.prefPane/Contents/XPCServices/com.apple.preference.network.remoteservice.xpc/Contents/MacOS/com.apple.preference.network.remoteservice",
    "/System/Library/PreferencePanes/ParentalControls.prefPane/Contents/XPCServices/com.apple.preferences.parentalcontrols.remoteservice.xpc/Contents/MacOS/com.apple.preferences.parentalcontrols.remoteservice",
    "/System/Library/PreferencePanes/PrintAndScan.prefPane/Contents/XPCServices/com.apple.preference.printfax.remoteservice.xpc/Contents/MacOS/com.apple.preference.printfax.remoteservice",
    "/System/Library/PreferencePanes/Security.prefPane/Contents/XPCServices/com.apple.preference.security.remoteservice.xpc/Contents/MacOS/com.apple.preference.security.remoteservice",
    "/System/Library/PreferencePanes/SharingPref.prefPane/Contents/XPCServices/com.apple.preferences.sharing.remoteservice.xpc/Contents/MacOS/com.apple.preferences.sharing.remoteservice",
    "/System/Library/PreferencePanes/Speech.prefPane/Contents/XPCServices/com.apple.preference.speech.remoteservice.xpc/Contents/MacOS/com.apple.preference.speech.remoteservice",
    "/System/Library/PreferencePanes/StartupDisk.prefPane/Contents/MacOS/StartupDisk",
    "/System/Library/PreferencePanes/StartupDisk.prefPane/Contents/XPCServices/com.apple.preference.startupdisk.remoteservice.xpc/Contents/MacOS/com.apple.preference.startupdisk.remoteservice",
    "/System/Library/PreferencePanes/TimeMachine.prefPane/Contents/XPCServices/com.apple.prefs.backup.remoteservice.xpc/Contents/MacOS/com.apple.prefs.backup.remoteservice",
    "/System/Library/PreferencePanes/UniversalAccessPref.prefPane/Contents/XPCServices/com.apple.preference.universalaccess.remoteservice.xpc/Contents/MacOS/com.apple.preference.universalaccess.remoteservice",
    "/System/Library/PrivateFrameworks/AOSKit.framework/Versions/A/XPCServices/com.apple.iCloudHelper.xpc/Contents/MacOS/com.apple.iCloudHelper",
    "/System/Library/PrivateFrameworks/SpeechObjects.framework/Versions/A/SpeechDataInstallerd.app/Contents/MacOS/SpeechDataInstallerd",
    "/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/UpdateSettingsTool",
    "/System/Library/PrivateFrameworks/SystemAdministration.framework/XPCServices/writeconfig.xpc/Contents/MacOS/writeconfig",
    "/System/Library/SystemProfiler/SPFirewallReporter.spreporter/Contents/MacOS/SPFirewallReporter",
    "/System/Library/UserEventPlugins/AutoTimeZone.plugin/Contents/MacOS/AutoTimeZone",
    "/usr/bin/tmutil",
    "/usr/libexec/locationd",
    "/usr/sbin/networksetup",
    "/usr/sbin/systemsetup",
    "/Applications/System Preferences.app/Contents/MacOS/System Preferences",
    NULL
};

/* hash tables for above lists */
struct injection *g_patch_table;
struct injection *g_restrict_table;

#define SOLVE_KERNEL_SYMBOL(string, pointer) if (solve_kernel_symbol((string), (void**)&(pointer))) { LOG_ERROR("Can't solve kernel symbol %s", (string)); return 0;}

#pragma mark TrustedBSD policies

/*
 * we can't initialize our kernel information structure here and solve symbols
 * because the first process hasn't been created yet.
 * if we access the filesystem from here things go really bad :-)
 */
static void
mario_policy_initbsd(struct mac_policy_conf *conf)
{
    /* initialize the hash table with binaries we want injected with fuzzing library */
    for (char **n = g_patch_injection_list; *n != NULL; n++)
    {
        struct injection *new = _MALLOC(sizeof(struct injection), M_TEMP, M_WAITOK | M_ZERO);
        if (new != NULL)
        {
            new->name = *n;
            HASH_ADD_KEYPTR(hh, g_patch_table, new->name, strlen(new->name), new);
        }
    }
    /* initialize the hash table with binaries we want injected with pause library */
    for (char **n = g_restrict_injection_list; *n != NULL; n++)
    {
        struct injection *new = _MALLOC(sizeof(struct injection), M_TEMP, M_WAITOK | M_ZERO);
        if (new != NULL)
        {
            new->name = *n;
            HASH_ADD_KEYPTR(hh, g_restrict_table, new->name, strlen(new->name), new);
        }
    }
}

/*
 * install MAC hook in cred_check_label_update_execve
 * this hook is called from exec_handle_sugid() inside exec_mach_imgact()
 * the process name is still not available (still contains parent's name)
 * because it's only set later. we can retrieve that information using the vnode.
 * NOTE: always return success value on this hook
 */
static int
mario_cred_check_label_update_execve(kauth_cred_t old,
                                     struct vnode *vp,
                                     struct label *vnodelabel,
                                     struct label *scriptvnodelabel,
                                     struct label *execlabel,
                                     struct proc *proc)
{
    /* read comment on inject_library_policy_initbsd to understand why this is here */
    if (g_initialized == 0)
    {
        /* initialize structure with kernel information to solve symbols */
        if (init_kernel_info())
        {
            /* in case of failure buffers are freed inside */
            return 0;
        }
        /* solve symbols we need */
        SOLVE_KERNEL_SYMBOL("_get_map_min", _get_map_min)
        SOLVE_KERNEL_SYMBOL("_get_task_map", _get_task_map)
        SOLVE_KERNEL_SYMBOL("_mach_vm_region", _mach_vm_region)
        SOLVE_KERNEL_SYMBOL("_mach_vm_protect", _mach_vm_protect)
        SOLVE_KERNEL_SYMBOL("_vm_map_read_user", _vm_map_read_user)
        SOLVE_KERNEL_SYMBOL("_vm_map_write_user", _vm_map_write_user)
        g_initialized++;
    }
    
    /* retrieve target name from the vnode vp in the arguments */
    char pathbuff[MAXPATHLEN] = {0};
    int pathbuff_len = sizeof(pathbuff);
    
    if (vn_getpath(vp, pathbuff, &pathbuff_len))
    {
        LOG_ERROR("Can't build path to vnode!");
        goto exit;
    }
    
    LOG_DEBUG("Loading %s", pathbuff);
    
    /* verify if current binary is in the injection hash tables */
    /* if not skip injection */
    uint32_t restricted = 0;
    struct injection *el = NULL;
    HASH_FIND_STR(g_patch_table, pathbuff, el);
    if (el != NULL)
    {
        goto injection;
    }
    /* nothing found in patch injection, test the restrict table */
    HASH_FIND_STR(g_restrict_table, pathbuff, el);
    if (el != NULL)
    {
        restricted = 1;
    }
    /* target not found, skip it */
    else
    {
        goto exit;
    }
    
injection:
    /* xcode bug */
    do {} while (0);
    /* retrieve base address of the target binary */
    vm_map_t task_map = _get_task_map(current_task());
    vm_map_offset_t base_address = _get_map_min(task_map);
    
    if (restricted == 0)
    {
        LOG_DEBUG("Injecting library into application %s located at address 0x%llx.", pathbuff, base_address);
        /* process the target binary and inject the dynamic library into its mach-o header */
        if (inject_library(task_map,base_address, pathbuff, pathbuff_len) != KERN_SUCCESS)
        {
            LOG_ERROR("Failed to inject library into %s.", pathbuff);
            /* XXX: return error ? */
            /* kill the process? */
        }
    }
    else
    {
        LOG_DEBUG("Injecting __RESTRICT into %s.", pathbuff);
        if (inject_restricted(task_map, base_address, pathbuff, pathbuff_len) != KERN_SUCCESS)
        {
            LOG_ERROR("Failed to inject __RESTRICT into %s.", pathbuff);
            /* XXX: return error ? */
            /* kill the process? */
        }
    }
    
exit:
    /* success, let loading proceed */
    return 0;
}

/* our handles */
static struct mac_policy_ops mario_ops =
{
    .mpo_policy_initbsd = mario_policy_initbsd,
    .mpo_cred_check_label_update_execve = mario_cred_check_label_update_execve,
};

static mac_policy_handle_t mario_handle;

static struct mac_policy_conf mario_policy_conf = {
    .mpc_name            = "mario",
    .mpc_fullname        = "Mario Kernel Extension",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &mario_ops,
    .mpc_loadtime_flags  = 0,
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0
};

#pragma mark Start and stop functions

kern_return_t mario_start(kmod_info_t * ki, void *d);
kern_return_t mario_stop(kmod_info_t *ki, void *d);

kern_return_t mario_start(kmod_info_t * ki, void *d)
{
    /* init the MAC policy */
    return mac_policy_register(&mario_policy_conf, &mario_handle, d);
}

kern_return_t mario_stop(kmod_info_t *ki, void *d)
{
    /* free g_kernel_info allocated buffers */
    cleanup_kernel_info();
    /* cleanup the hash tables */
    struct injection *el, *tmp;
    HASH_ITER(hh, g_patch_table, el, tmp)
    {
        HASH_DEL(g_patch_table, el);
        _FREE(el, M_TEMP);
    }
    HASH_ITER(hh, g_restrict_table, el, tmp)
    {
        HASH_DEL(g_restrict_table, el);
        _FREE(el, M_TEMP);
    }
    /* remove the MAC policy, game over */
    return mac_policy_unregister(mario_handle);
}
