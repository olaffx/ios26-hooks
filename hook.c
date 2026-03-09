#include <fishhook.h>
#include <xpc/xpc.h>
#include <spawn.h>
#include <dirent.h>
#include <sys/mount.h>
#import <IOKit/IOKitLib.h>
#include <sys/clonefile.h>
#import <mach-o/dyld.h>
#include <os/log.h>

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE 0x48
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE 0x4C
#define JETSAM_MULTIPLIER 3
#define SYSCALL_CSOPS 0xA9
#define SYSCALL_CSOPS_AUDITTOKEN 0xAA
#define POSIX_SPAWNATTR_OFF_LAUNCH_TYPE 0x50
#define ROOT_PREBOOT_PATH "/System/Volumes/Preboot"
#define JB_BASE_PATH "/private/preboot/jb"

#define HOOK_LOG(fmt, ...) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, "NLR_26: " fmt, ##__VA_ARGS__)
#define HOOK_ERR(fmt, ...) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_ERROR, "NLR_26 ERROR: " fmt, ##__VA_ARGS__)

int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attr, uint8_t launch_type);
int (*orig_posix_spawn)(pid_t * __restrict pid, const char * __restrict path,
                        const posix_spawn_file_actions_t *file_actions,
                        const posix_spawnattr_t * __restrict attrp,
                        char *const argv[ __restrict], char *const envp[ __restrict]);
int (*orig_posix_spawnp)(pid_t *restrict pid, const char *restrict pathx, 
                         const posix_spawn_file_actions_t *restrict file_actions, 
                         const posix_spawnattr_t *restrict attrp, 
                         char *const argv[restrict], char *const envp[restrict]);
xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t xdict, const char *key);
int (*memorystatus_control_orig)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);
char *sandbox_extension_issue_mach(const char *extension_class, const char *name, uint32_t flags);

char *boot_hash = NULL;
char launchdPath[PATH_MAX];
char xpcPath[PATH_MAX];

int get_boot_manifest_hash(char hash[97])
{
    const UInt8 *bytes;
    CFIndex length;
    io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    if (!MACH_PORT_VALID(chosen)) {
        HOOK_ERR("Failed to open IORegistryEntry");
        return 1;
    }
    
    CFDataRef manifestHash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    IOObjectRelease(chosen);
    
    if (manifestHash == NULL || CFGetTypeID(manifestHash) != CFDataGetTypeID()) {
        if (manifestHash) CFRelease(manifestHash);
        HOOK_ERR("Failed to get boot-manifest-hash");
        return 1;
    }
    
    length = CFDataGetLength(manifestHash);
    bytes = CFDataGetBytePtr(manifestHash);
    for (int i = 0; i < length && i < 48; i++) {
        snprintf(&hash[i * 2], 3, "%02X", bytes[i]);
    }
    CFRelease(manifestHash);
    HOOK_LOG("Boot manifest hash: %s", hash);
    return 0;
}

char* return_boot_manifest_hash_main(void) {
    static char hash[97];
    int ret = get_boot_manifest_hash(hash);
    if (ret != 0) {
        HOOK_ERR("Could not get boot manifest hash");
        return "";
    }
    static char result[115];
    sprintf(result, "%s/%s", ROOT_PREBOOT_PATH, hash);
    return result;
}

int hooked_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int rv = syscall(SYSCALL_CSOPS, pid, ops, useraddr, usersize);
    if (rv != 0) return rv;
    if (ops == 0 && useraddr != NULL) {
        uint32_t *flags = (uint32_t *)useraddr;
        uint32_t originalFlags = *flags;
        *flags |= 0x4000000;
        if ((originalFlags & 0x4000000) == 0) {
            HOOK_LOG("csops: added CS_DEBUGGED for PID %d", pid);
        }
    }
    return rv;
}

int hooked_csops_audittoken(pid_t pid, unsigned int ops, void * useraddr, size_t usersize, audit_token_t * token) {
    int rv = syscall(SYSCALL_CSOPS_AUDITTOKEN, pid, ops, useraddr, usersize, token);
    if (rv != 0) return rv;
    if (ops == 0 && useraddr != NULL) {
        uint32_t *flags = (uint32_t *)useraddr;
        *flags |= 0x4000000;
    }
    return rv;
}

int envbuf_find(const char *envp[], const char *name)
{
    if (!envp) return -1;
    unsigned long nameLen = strlen(name);
    int k = 0;
    const char *env = envp[k++];
    while (env) {
        unsigned long envLen = strlen(env);
        if (envLen > nameLen) {
            if (!strncmp(env, name, nameLen) && env[nameLen] == '=') {
                return k-1;
            }
        }
        env = envp[k++];
    }
    return -1;
}

int envbuf_len(const char *envp[])
{
    if (!envp) return 1;
    int k = 0;
    while (envp[k]) k++;
    return k + 1;
}

void envbuf_setenv(char **envpp[], const char *name, const char *value)
{
    if (!envpp) return;
    
    char **envp = *envpp;
    if (!envp) {
        envp = malloc(sizeof(char *));
        envp[0] = NULL;
    }

    char *envToSet = malloc(strlen(name) + strlen(value) + 2);
    sprintf(envToSet, "%s=%s", name, value);

    int existingEnvIndex = envbuf_find((const char **)envp, name);
    if (existingEnvIndex >= 0) {
        free(envp[existingEnvIndex]);
        envp[existingEnvIndex] = envToSet;
    } else {
        int prevLen = envbuf_len((const char **)envp);
        *envpp = realloc(envp, (prevLen + 1) * sizeof(char *));
        envp = *envpp;
        envp[prevLen - 1] = envToSet;
        envp[prevLen] = NULL;
    }
}

char **envbuf_mutcopy(const char *envp[])
{
    if (!envp) return NULL;
    int len = envbuf_len(envp);
    char **envcopy = malloc(len * sizeof(char *));
    for (int i = 0; i < len - 1; i++) {
        envcopy[i] = strdup(envp[i]);
    }
    envcopy[len - 1] = NULL;
    return envcopy;
}

void envbuf_free(char *envp[])
{
    if (!envp) return;
    int len = envbuf_len((const char**)envp);
    for (int i = 0; i < len - 1; i++) {
        free(envp[i]);
    }
    free(envp);
}

void increaseJetsamLimits(posix_spawnattr_t *attrp) {
    if (!attrp || !*attrp) return;
    
    uint8_t *attrStruct = *attrp;
    int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
    if (memlimit_active != -1) {
        int new_limit = memlimit_active * JETSAM_MULTIPLIER;
        *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = new_limit;
        HOOK_LOG("Increased active memory limit: %d -> %d", memlimit_active, new_limit);
    }
    
    int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
    if (memlimit_inactive != -1) {
        *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * JETSAM_MULTIPLIER;
    }
}

void writeSandboxExtensionsToPlist() {
    char *sandboxPath = JB_BASE_PATH;
    char *filePath = "/System/Library/VideoCodecs/tmp/NLR_SANDBOX_EXTENSIONS";
    char extensionString[762];

    HOOK_LOG("Generating sandbox extensions for path: %s", sandboxPath);
    
    char *sb1 = sandbox_extension_issue_file("com.apple.app-sandbox.read-write", sandboxPath, 0);
    char *sb2 = sandbox_extension_issue_file("com.apple.sandbox.executable", sandboxPath, 0);
    char *sb3 = sandbox_extension_issue_mach("com.apple.security.exception.mach-lookup.global-name", 
                                              "com.hrtowii.jitterd.ios26", 0);
    
    if (!sb1 || !sb2 || !sb3) {
        HOOK_ERR("Failed to generate sandbox extensions");
        if (sb1) free(sb1);
        if (sb2) free(sb2);
        if (sb3) free(sb3);
        return;
    }
    
    snprintf(extensionString, sizeof(extensionString), "%s|%s|%s", sb1, sb2, sb3);
    
    free(sb1);
    free(sb2);
    free(sb3);
    
    char dirPath[PATH_MAX];
    strcpy(dirPath, filePath);
    char *lastSlash = strrchr(dirPath, '/');
    if (lastSlash) {
        *lastSlash = '\0';
        mkdir(dirPath, 0755);
    }
    
    FILE *file = fopen(filePath, "w");
    if (file) {
        fwrite(extensionString, 1, strlen(extensionString) + 1, file);
        fclose(file);
        HOOK_LOG("Saved sandbox extensions to %s", filePath);
    } else {
        HOOK_ERR("Could not open file for writing: %s", filePath);
    }
}

void strip_last_component(char *path) {
    char *last_slash = strrchr(path, '/');
    if (last_slash) {
        *(last_slash + 1) = '\0';
    }
}

int hooked_posix_spawn(pid_t *pid, const char *path, 
                       const posix_spawn_file_actions_t *file_actions, 
                       posix_spawnattr_t *attrp, 
                       char *argv[], char *const envp[]) {
    
    HOOK_LOG("posix_spawn: %s", path ? path : "NULL");
    
    if (path && !strncmp(path, "/var/containers/Bundle/Application/", 35)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "%s_NATHANLR", path);

        if (!access(newPath, F_OK)) {
            HOOK_LOG("Redirecting to jailbreak version: %s", newPath);
            
            char dylibPath[PATH_MAX];
            snprintf(dylibPath, sizeof(dylibPath), "%s", path);
            strip_last_component(dylibPath);
            snprintf(dylibPath, sizeof(dylibPath), "%s/appstorehelper.dylib", dylibPath);
            
            char bakPath[PATH_MAX];
            snprintf(bakPath, sizeof(bakPath), "%s.bak", path);
            
            rename(path, bakPath);
            clonefile(newPath, path, 0);
            
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", dylibPath);
            increaseJetsamLimits(attrp);
            
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            
            envbuf_free(envc);
            rename(bakPath, path);
            return ret;
        }
    }
    else if (path && !strncmp(path, "/Applications/", 14)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/Applications/%s", path + 14);

        if (!access(newPath, F_OK)) {
            HOOK_LOG("Redirecting app: %s -> %s", path, newPath);
            path = newPath;
            argv[0] = (char *)path;
            
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", 
                         "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    }
    else if (path && strstr(path, "/jb/Applications/")) {
        char **envc = envbuf_mutcopy((const char **)envp);
        envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", 
                     "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
        increaseJetsamLimits(attrp);
        
        int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
        envbuf_free(envc);
        return ret;
    }
    else if (path && !strcmp(path, "/sbin/launchd")) {
        if (access(launchdPath, F_OK) == 0) {
            HOOK_LOG("Redirecting launchd: %s -> %s", path, launchdPath);
            path = launchdPath;
            argv[0] = (char *)path;
            if (attrp) {
                posix_spawnattr_set_launch_type_np(attrp, 0);
            }
        }
    }
    
    return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

xpc_object_t hook_xpc_dictionary_get_value(xpc_object_t dict, const char *key) {
    xpc_object_t retval = xpc_dictionary_get_value_orig(dict, key);
    
    if (!strcmp(key, "Paths")) {
        if (xpc_get_type(retval) == XPC_TYPE_ARRAY) {
            HOOK_LOG("Adding launchd paths to XPC");
            xpc_array_set_string(retval, XPC_ARRAY_APPEND, "/var/jb/basebins/LaunchDaemons");
            xpc_array_set_string(retval, XPC_ARRAY_APPEND, "/var/jb/Library/LaunchDaemons");
        }
    }

    return retval;
}

int memorystatus_control_hook(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize)
{
    if (command == MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT) {
        HOOK_LOG("Blocking SET_JETSAM_TASK_LIMIT for PID %d", pid);
        return 0;
    }
    return memorystatus_control_orig(command, pid, flags, buffer, buffersize);
}

struct rebinding rebindings[6] = {
    {"csops", hooked_csops, NULL},
    {"csops_audittoken", hooked_csops_audittoken, NULL},
    {"posix_spawn", hooked_posix_spawn, (void *)&orig_posix_spawn},
    {"posix_spawnp", hooked_posix_spawn, (void *)&orig_posix_spawnp},
    {"xpc_dictionary_get_value", hook_xpc_dictionary_get_value, (void *)&xpc_dictionary_get_value_orig},
    {"memorystatus_control", memorystatus_control_hook, (void *)&memorystatus_control_orig},
};

__attribute__((constructor)) static void init(int argc, char **argv) {
    HOOK_LOG("=== LAUNCHD HOOK FOR iOS 26.1 LOADED ===");
    HOOK_LOG("PID: %d, argv[0]: %s", getpid(), argv ? argv[0] : "NULL");
    
    if (getpid() != 1) {
        HOOK_LOG("Child process (PID %d) - cleaning up", getpid());
        unsetenv("DYLD_INSERT_LIBRARIES");
    } else {
        HOOK_LOG("=== LAUNCHD INITIALIZATION (PID 1) ===");
        
        boot_hash = strdup(return_boot_manifest_hash_main());
        if (!boot_hash || strlen(boot_hash) == 0) {
            HOOK_ERR("Could not get boot hash - using default");
            boot_hash = strdup("/private/preboot");
        }
        
        snprintf(launchdPath, sizeof(launchdPath), "%s/jb/System/Library/SysBins/launchd", boot_hash);
        snprintf(xpcPath, sizeof(xpcPath), "%s/jb/System/Library/SysBins/xpcproxy", boot_hash);
        
        HOOK_LOG("launchdPath: %s", launchdPath);
        HOOK_LOG("xpcPath: %s", xpcPath);
        
        if (access("/var/jb", F_OK) != 0) {
            char jbTarget[PATH_MAX];
            snprintf(jbTarget, sizeof(jbTarget), "%s/jb", boot_hash);
            
            HOOK_LOG("Creating symlink /var/jb -> %s", jbTarget);
            symlink(jbTarget, "/var/jb");
            lchown("/var/jb", 0, 0);
        }
        
        HOOK_LOG("Mounting filesystems...");
        
        unmount("/System/Library/VideoCodecs/lib/", MNT_FORCE);
        unmount("/System/Library/VideoCodecs/tmp", MNT_FORCE);
        unmount("/System/Library/VideoCodecs/", MNT_FORCE);
        
        mount("bindfs", "/System/Library/VideoCodecs", MNT_RDONLY, 
              (void *)"/private/var/jb/System/Library");
        
        struct tmpfs_mount_args {
            uint64_t max_pages;
            uint64_t max_nodes;
            uint64_t case_insensitive;
        } arg = {
            .max_pages = (20000 / 16384), 
            .max_nodes = UINT8_MAX, 
            .case_insensitive = 0
        };
        mount("tmpfs", "/System/Library/VideoCodecs/tmp", 0, &arg);
        
        mount("bindfs", "/System/Library/VideoCodecs/lib", MNT_RDONLY, 
              (void *)"/private/var/jb/usr/lib");
        
        HOOK_LOG("Filesystems mounted");
        
        writeSandboxExtensionsToPlist();
        
        HOOK_LOG("Hooking symbols...");
        int ret = rebind_symbols(rebindings, 6);
        if (ret == 0) {
            HOOK_LOG("Hooking successful");
        } else {
            HOOK_ERR("Hooking failed: %d", ret);
        }
    }
    
    HOOK_LOG("=== INITIALIZATION COMPLETE ===");
}