// SPDX-License-Identifier: GPL-2.0
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <csignal>
#include <pthread.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <optional>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include "Driver.h"

namespace {
int g_fails = 0, g_passes = 0, g_skips = 0;
void report(const char* tag, const char* name, const char* fmt, ...) { va_list ap; va_start(ap, fmt); char buf[512]; std::vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap); std::printf("[%s] %-40s %s\n", tag, name, buf); if (tag[0] == 'P') ++g_passes; else if (tag[0] == 'F') ++g_fails; else ++g_skips; }
#define PASS(name, ...) report("PASS", name, __VA_ARGS__)
#define FAIL(name, ...) report("FAIL", name, __VA_ARGS__)
#define SKIP(name, ...) report("SKIP", name, __VA_ARGS__)

bool require_hwbp(const char* name) { if (driver.hwbpAvailable()) return true; SKIP(name, "hwbp unavailable"); return false; }
bool test_open() { errno = 0; if (!driver.open()) { FAIL("S1_driver_open", "errno=%d (%s)", errno, std::strerror(errno)); return false; } PASS("S1_driver_open", "handshake ok"); return true; }
bool file_grep(const char* path, const char* needle) { FILE* f = std::fopen(path, "r"); if (!f) return false; char line[512]; while (std::fgets(line, sizeof(line), f)) { if (std::strstr(line, needle)) { std::fclose(f); return true; } } std::fclose(f); return false; }
bool dir_has(const char* path, const char* needle) { std::string p = std::string(path) + "/" + needle; struct stat st; return stat(p.c_str(), &st) == 0; }
void test_stealth_surface() { const char* needle = "my_driver"; const char* alt = "my-driver"; if (file_grep("/proc/modules", needle) || file_grep("/proc/modules", alt)) FAIL("S2_proc_modules_hidden", "still visible in /proc/modules"); else PASS("S2_proc_modules_hidden", "not listed"); if (dir_has("/sys/module", "my_driver") || dir_has("/sys/module", "my-driver")) FAIL("S2_sys_module_hidden", "still visible in /sys/module"); else PASS("S2_sys_module_hidden", "not listed"); if (file_grep("/proc/vmallocinfo", "my_driver")) FAIL("S2_vmallocinfo_hidden", "vmap area still named"); else PASS("S2_vmallocinfo_hidden", "no matching entry"); }

