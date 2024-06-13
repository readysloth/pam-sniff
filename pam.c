#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "pam.skel.h"
#include "pam-def.bpf.h"

#define NAMESPACE(PROJECT, FUNC) PROJECT ## _bpf__ ## FUNC

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

static void handle_lost(void *ctx, int cpu, __u64 lost)
{
  fprintf(stdout, "Lost %llu events on CPU #%d!\n", lost, cpu);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
  output_info_t *output_info = data;
  char fmt[] = "%s(%d)->%s: ";
  fprintf(
      stdout,
      fmt,
      output_info->gen_info.procname,
      output_info->gen_info.pid,
      output_info->gen_info.fname);
  fprintf(stdout, "%s\n", output_info->heap.buffer);
}


int main(int argc, char **argv)
{
  struct pam_bpf *pam_skel;
  int err, i;
  LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  pam_skel = NAMESPACE(pam, open_and_load)();
  if (!pam_skel) {
    fprintf(stderr, "Failed to open and load BPF pam_skeleton\n");
    return 1;
  }

#define ATTACH_TO(FUNC, BPF_HANDLER, IS_RETPROBE, BINARY) \
  { uprobe_opts.func_name = FUNC; \
    uprobe_opts.retprobe = IS_RETPROBE; \
    pam_skel->links. BPF_HANDLER = bpf_program__attach_uprobe_opts(pam_skel->progs. BPF_HANDLER, -1, BINARY, 0, &uprobe_opts); \
    if (!pam_skel->links. BPF_HANDLER) { err = -errno; fprintf(stderr, "Failed to attach uprobe to %s:%s: %d\n", BINARY, FUNC, err);} }

  for(int i = 1; i < argc; i++){
    ATTACH_TO("pam_sm_authenticate", pam_sm_authenticate, false, argv[i]);
    ATTACH_TO("pam_sm_setcred", pam_sm_setcred, false, argv[i]);
    ATTACH_TO("pam_sm_acct_mgmt", pam_sm_acct_mgmt, false, argv[i]);
    ATTACH_TO("pam_sm_open_session", pam_sm_open_session, false, argv[i]);
    ATTACH_TO("pam_sm_close_session", pam_sm_close_session, false, argv[i]);
    ATTACH_TO("pam_sm_chauthtok", pam_sm_chauthtok, false, argv[i]);

    ATTACH_TO("pam_sm_authenticate", pam_sm_ret, true, argv[i]);
    ATTACH_TO("pam_sm_setcred", pam_sm_ret, true, argv[i]);
    ATTACH_TO("pam_sm_acct_mgmt", pam_sm_ret, true, argv[i]);
    ATTACH_TO("pam_sm_open_session", pam_sm_ret, true, argv[i]);
    ATTACH_TO("pam_sm_close_session", pam_sm_ret, true, argv[i]);
    ATTACH_TO("pam_sm_chauthtok", pam_sm_ret, true, argv[i]);
  }

  /* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
   * NOTICE: we provide path and symbol info in SEC for BPF programs
   */
  err = NAMESPACE(pam, attach)(pam_skel);
  if (err) {
    fprintf(stderr, "Failed to auto-attach BPF pam_skeleton: %d\n", err);
    goto cleanup;
  }

  struct perf_buffer *pbuf = perf_buffer__new(
      bpf_map__fd(pam_skel->maps.OUTPUT), 128, print_bpf_output, handle_lost, NULL, NULL
  );
  if (!pbuf) {
    err = -errno;
    fprintf(stderr, "Failed to open perf buffer: %d\n", err);
    goto cleanup;
  }

  while (true) {
    err = perf_buffer__poll(pbuf, 1);
    if (err < 0 && err != -EINTR) {
      fprintf(stderr, "Error while polling perf buffer: %s\n", strerror(err));
      goto cleanup;
    }
    err = 0;
  }

cleanup:
  perf_buffer__free(pbuf);
  NAMESPACE(pam, destroy)(pam_skel);
  return -err;
}
