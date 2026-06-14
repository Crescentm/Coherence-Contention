#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HOST_RUNNER_PRELOAD 1
#include "host_runner_preload_shared.h"

/* Entry-only preload file:
 * shared runtime helpers live in src/host_runner_modes/common_runtime.c;
 * each mode implementation lives in src/host_runner_modes/mode_*.c.
 */
__attribute__((constructor)) static void hr_init(void) {
  pthread_t tid;
  const char *mode;
  int rc = 0;

  setvbuf(stderr, NULL, _IONBF, 0);
  if (!getenv("HR_OUTDIR"))
    return;

  /* Prevent duplicate preload threads in fork/exec children. */
  {
    char lk[512];
    int lfd;
    snprintf(lk, sizeof(lk), "%s/.hr_preload.lock", getenv("HR_OUTDIR"));
    lfd = open(lk, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (lfd < 0)
      return;
    close(lfd);
  }

  mode = getenv("HR_MODE");
  if (mode && strcmp(mode, "all") == 0) {
    fprintf(stderr, "[HR] preload mode=all\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_all, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(all) failed: %s\n", strerror(rc));
  } else if (mode && strcmp(mode, "toggle") == 0) {
    fprintf(stderr, "[HR] host_runner_preload injected (TOGGLE MODE), starting "
                    "thread...\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_toggle, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(toggle) failed: %s\n", strerror(rc));
  } else if (mode && strcmp(mode, "contention") == 0) {
    fprintf(stderr, "[HR] preload mode=contention\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_contention, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(contention) failed: %s\n",
              strerror(rc));
  } else if (mode && strcmp(mode, "contention_cacheable") == 0) {
    fprintf(stderr, "[HR] preload mode=contention_cacheable\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_contention_cacheable, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(contention_cacheable) failed: %s\n",
              strerror(rc));
  } else if (mode && strcmp(mode, "contention_cmb") == 0) {
    fprintf(stderr, "[HR] preload mode=contention_cmb\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_contention_cmb, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(contention_cmb) failed: %s\n",
              strerror(rc));
  } else if (mode && strcmp(mode, "contention_spatial") == 0) {
    fprintf(stderr, "[HR] preload mode=contention_spatial\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_contention_spatial, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(contention_spatial) failed: %s\n",
              strerror(rc));
  } else if (mode && strcmp(mode, "blind") == 0) {
    fprintf(stderr, "[HR] preload mode=blind\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_blind, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(blind) failed: %s\n", strerror(rc));
  } else if (mode && strcmp(mode, "pc") == 0) {
    fprintf(stderr, "[HR] preload mode=pc (LLC Prime+Count)\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_pc, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(pc) failed: %s\n", strerror(rc));
  } else if (mode && strcmp(mode, "nptctl") == 0) {
    fprintf(stderr, "[HR] preload mode=nptctl\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_nptctl, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(nptctl) failed: %s\n",
              strerror(rc));
  } else if (mode && strcmp(mode, "aes_toggle") == 0) {
    fprintf(stderr, "[HR] preload mode=aes_toggle\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_aes_toggle, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(aes_toggle) failed: %s\n",
              strerror(rc));
  } else {
    fprintf(stderr, "[HR] preload mode=single\n");
    rc = pthread_create(&tid, NULL, hr_main_thread_single, NULL);
    if (rc != 0)
      fprintf(stderr, "[HR] pthread_create(single) failed: %s\n", strerror(rc));
  }
  pthread_detach(tid);
}
