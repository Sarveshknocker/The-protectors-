/* Rule corpus (C firmware / native). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle(char *input, char *user_msg, char *cmd, size_t count, size_t size, char *name) {
    char buf[32];
    /* ruleid: c.banned-functions */
    strcpy(buf, input);
    /* ok: c.banned-functions, c.format-string */
    snprintf(buf, sizeof buf, "%s", input);
    /* ruleid: c.format-string */
    printf(user_msg);
    /* ok: c.format-string */
    printf("%s", user_msg);
    /* ruleid: c.command-exec */
    system(cmd);
    /* ok: c.command-exec */
    system("reboot");
    /* ruleid: c.alloc-overflow */
    void *p = malloc(count * size);
    /* ok: c.alloc-overflow */
    void *q = calloc(count, size);
    /* ruleid: c.insecure-temp */
    tmpnam(name);
    /* ok: c.insecure-temp */
    int fd = mkstemp(name);
}

void connect_cloud(void) {
    /* ruleid: fw.tls-no-verify */
    client.setInsecure();
    /* ok: fw.tls-no-verify */
    client.setCACert(root_ca);
    /* ruleid: fw.debug-interfaces */
    HAL_DBGMCU_EnableDBGStopMode();
    /* ok: fw.debug-interfaces */
    HAL_RCC_DeInit();
}

void ota(void) {
    /* ruleid: fw.insecure-ota */
    httpUpdate.update(client, "http://fw.acme.io/firmware.bin");
}
