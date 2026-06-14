#include <stdio.h>

/*
 * host_runner.c
 *
 * 当前实验路径统一使用 LD_PRELOAD 注入的 host_runner_preload.so。
 * 该独立二进制保留为占位入口，避免旧构建链或脚本找不到目标文件。
 */
int main(void) {
  fprintf(stderr,
          "host_runner is deprecated in this project path.\n"
          "Use build/libhost_runner.so via LD_PRELOAD.\n");
  return 0;
}
