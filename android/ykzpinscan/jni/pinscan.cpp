// YKZ-Pinscan — per-app Conscrypt-APEX CA bind for SSL-pinning posture scanning.
//
// The target package(s) are read from a config file (/data/adb/ykzpinscan/targets,
// one package per line); nothing is hardcoded.
// For any listed package, at preAppSpecialize (still uid 0 + CAP_SYS_ADMIN, before the
// app is specialised) it unshares the mount namespace and bind-mounts a prepared trust
// store (the device's real roots + the research CA) over the Conscrypt APEX cacerts dir.
// The app then trusts the proxy's CA, so any TLS rejection observed at the proxy is a
// pinning check ABOVE the trust store — the signal the pinscan harness classifies.
//
// Research / authorised-engagement use only. Boot-safe: only acts at app fork.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <android/log.h>
#include <sys/mount.h>
#include <sched.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "zygisk.hpp"
using zygisk::Api; using zygisk::AppSpecializeArgs; using zygisk::ServerSpecializeArgs;
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "YKZPINSCAN", __VA_ARGS__)

static const char *TARGETS_FILE = "/data/adb/ykzpinscan/targets";
static const char *SRC   = "/data/adb/modules/ykzpinscan/system_cacerts";
static const char *APEX  = "/apex/com.android.conscrypt/cacerts";

// Is `nm` listed (exact match) in the targets file? Blank lines / '#' comments ignored.
static bool is_target(const char *nm) {
    if (!nm) return false;
    FILE *f = fopen(TARGETS_FILE, "r");
    if (!f) return false;
    char line[256];
    bool hit = false;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        size_t n = strlen(p);
        while (n && (p[n-1] == '\n' || p[n-1] == '\r' || p[n-1] == ' ' || p[n-1] == '\t')) p[--n] = 0;
        if (n == 0 || p[0] == '#') continue;
        if (strcmp(p, nm) == 0) { hit = true; break; }
    }
    fclose(f);
    return hit;
}

// count_cas returns how many <hash>.0 trust-store entries are visible at d, as a
// post-bind sanity signal (stock roots + the research CA we added).
static int count_cas(const char *d) {
    DIR *dir = opendir(d);
    if (!dir) return -1;
    int n = 0; dirent *e;
    while ((e = readdir(dir))) {
        size_t l = strlen(e->d_name);
        if (l >= 2 && e->d_name[l-2] == '.' && e->d_name[l-1] == '0') n++;
    }
    closedir(dir);
    return n;
}

class YkzPinscan : public zygisk::ModuleBase {
public:
    void onLoad(Api *a, JNIEnv *e) override { api = a; env = e; }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *nm = env->GetStringUTFChars(args->nice_name, nullptr);
        char name[128]; name[0] = 0;
        bool t = false;
        if (nm) {
            strncpy(name, nm, sizeof(name) - 1);
            t = is_target(name);
            env->ReleaseStringUTFChars(args->nice_name, nm);
        }
        if (!t) { api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY); return; }

        if (unshare(CLONE_NEWNS) != 0) LOG("[%s] unshare failed: %s", name, strerror(errno));
        if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0)
            LOG("[%s] make-private failed", name);
        if (mount(SRC, APEX, nullptr, MS_BIND | MS_REC, nullptr) == 0) {
            LOG("[%s] CA bind OK -> %d trusted CAs (pinscan target)", name, count_cas(APEX));
        } else {
            LOG("[%s] CA bind FAILED: %s", name, strerror(errno));
        }
    }

    void preServerSpecialize(ServerSpecializeArgs *) override {
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};
REGISTER_ZYGISK_MODULE(YkzPinscan)
