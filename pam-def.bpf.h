#define XSTR(s) STR(s)
#define STR(s) #s

#define min(x, y) ((x) < (y) ? (x) : (y))
#define DEBUG_TRACE(MSG, ...) \
	bpf_printk("DEBUG_TRACE:%s:%d " MSG, __FILE__, __LINE__, ## __VA_ARGS__)

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE (size_t)2048
#endif

#ifndef SMALL_BUF_SIZE
#define SMALL_BUF_SIZE (size_t)32
#endif

typedef char small_str[SMALL_BUF_SIZE];
typedef char heap_buffer_t[MAX_BUF_SIZE];

typedef struct {
    heap_buffer_t buffer;
    size_t taken;
} heap_t;


#define SMALL_STR_SIZE \
    sizeof(small_str)
#define HEAP_SIZE \
    (sizeof(((heap_t*)NULL)->buffer))
#define FREE_HEAP_SIZE(HEAP_PTR) \
    (HEAP_SIZE - (HEAP_PTR)->taken)
#define FREE_HEAP_PTR(HEAP_PTR) \
    ((HEAP_PTR)->buffer + (HEAP_PTR)->taken)

typedef struct {
    __u64 pid;
    small_str procname;
    small_str fname;
} generic_info_t;

typedef struct {
    generic_info_t gen_info;
    heap_t heap;
} output_info_t;


/* Private structure
 * Some pointers made void to reduce complexity
 */
typedef struct pam_handle {
    char *authtok;
    unsigned caller_is;
    void *pam_conversation;
    char *oldauthtok;
    char *prompt;
    char *service_name;
    char *user;
    char *rhost;
    char *ruser;
    char *tty;
    char *xdisplay;
    char *authtok_type;

    /* cutoff */
} pam_handle_t;

#define PAM_SILENT 0x8000U
#define PAM_DISALLOW_NULL_AUTHTOK 0x0001U
#define PAM_ESTABLISH_CRED 0x0002U
#define PAM_DELETE_CRED 0x0004U
#define PAM_REINITIALIZE_CRED 0x0008U
#define PAM_REFRESH_CRED 0x0010U
#define PAM_CHANGE_EXPIRED_AUTHTOK 0x0020U

#define PAM_SUCCESS 0
#define PAM_OPEN_ERR 1
#define PAM_SYMBOL_ERR 2
#define PAM_SERVICE_ERR 3
#define PAM_SYSTEM_ERR 4
#define PAM_BUF_ERR 5
#define PAM_PERM_DENIED 6
#define PAM_AUTH_ERR 7
#define PAM_CRED_INSUFFICIENT 8
#define PAM_AUTHINFO_UNAVAIL 9
#define PAM_USER_UNKNOWN 10
#define PAM_MAXTRIES 11
#define PAM_NEW_AUTHTOK_REQD 12
#define PAM_ACCT_EXPIRED 13
#define PAM_SESSION_ERR 14
#define PAM_CRED_UNAVAIL 15
#define PAM_CRED_EXPIRED 16
#define PAM_CRED_ERR 17
#define PAM_NO_MODULE_DATA 18
#define PAM_CONV_ERR 19
#define PAM_AUTHTOK_ERR 20
#define PAM_AUTHTOK_RECOVERY_ERR 21
#define PAM_AUTHTOK_LOCK_BUSY 22
#define PAM_AUTHTOK_DISABLE_AGING 23
#define PAM_TRY_AGAIN 24
#define PAM_IGNORE 25
#define PAM_ABORT 26
#define PAM_AUTHTOK_EXPIRED 27
#define PAM_MODULE_UNKNOWN 28
#define PAM_BAD_ITEM 29
#define PAM_CONV_AGAIN 30
#define PAM_INCOMPLETE 31
