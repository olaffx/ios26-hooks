#include <xpc/xpc.h>
#include <mach/mach.h>
#include <os/log.h>

#define PT_DETACH 11
#define PT_ATTACHEXC 14
#define PT_KILL 8
#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#define JBD_MSG_PROC_SET_DEBUGGED 23
#define JIT_SERVICE_NAME "com.hrtowii.jitterd.ios26"

#define JITTER_LOG(fmt, ...) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, "JITTER_26: " fmt, ##__VA_ARGS__)
#define JITTER_ERR(fmt, ...) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_ERROR, "JITTER_26 ERROR: " fmt, ##__VA_ARGS__)

int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void * _Nullable buffer, size_t buffersize);
kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service, mach_port_t *server_port);

int enableJIT(pid_t pid)
{
    JITTER_LOG("enableJIT called for PID: %d", pid);
    
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) {
        JITTER_ERR("ptrace PT_ATTACHEXC failed for PID %d", pid);
        return -1;
    }
    
    for (int retries = 0; retries < 50; retries++) {
        usleep(1000);
        if (!ptrace(PT_DETACH, pid, 0, 0)) {
            JITTER_LOG("JIT enabled for PID %d after %d attempts", pid, retries + 1);
            return 0;
        }
    }
    
    JITTER_ERR("Failed to enable JIT for PID %d after 50 attempts, killing", pid);
    ptrace(PT_KILL, pid, 0, 0);
    return -1;
}

void jitterd_received_message(mach_port_t machPort)
{
    xpc_object_t message = NULL;
    int err = xpc_pipe_receive(machPort, &message);
    if (err != 0) {
        JITTER_ERR("xpc_pipe_receive error %d", err);
        return;
    }
    
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    if (!reply) {
        JITTER_ERR("Failed to create reply");
        xpc_release(message);
        return;
    }
    
    if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
        if (xpc_dictionary_get_value(message, "pid")) {
            int64_t pid = xpc_dictionary_get_int64(message, "pid");
            int64_t result = enableJIT((pid_t)pid);
            xpc_dictionary_set_int64(reply, "result", result);
            JITTER_LOG("Processed request for PID %lld with result %lld", pid, result);
        } else {
            JITTER_ERR("Message missing pid key");
            xpc_dictionary_set_int64(reply, "result", -1);
        }
    } else {
        JITTER_ERR("Received non-dictionary message");
        xpc_dictionary_set_int64(reply, "result", -1);
    }
    
    xpc_pipe_routine_reply(reply);
    xpc_release(message);
    xpc_reply(reply);
}

__attribute__((constructor)) static void init() {
    JITTER_LOG("Jitterd constructor running");
    memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid(), 10, NULL, 0);
    JITTER_LOG("Jetsam high water mark set");
}

int main(int argc, char* argv[])
{
    JITTER_LOG("=== JITTERD FOR iOS 26.1 STARTING ===");
    JITTER_LOG("PID: %d", getpid());
    
    mach_port_t machPort = 0;
    kern_return_t kr = bootstrap_check_in(bootstrap_port, JIT_SERVICE_NAME, &machPort);
    
    if (kr != KERN_SUCCESS) {
        JITTER_ERR("bootstrap_check_in failed: %d", kr);
        return 1;
    }
    
    JITTER_LOG("Service registered: %s", JIT_SERVICE_NAME);
    
    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, machPort, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(source, ^{
        jitterd_received_message(machPort);
    });
    dispatch_resume(source);
    
    JITTER_LOG("Jitterd running, waiting for requests...");
    dispatch_main();
    
    return 0;
}