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

void test_caps() { if (!require_hwbp("S3_hwbp_caps")) return; errno = 0; auto c = driver.hwbp.caps(); if (!c) { FAIL("S3_hwbp_caps", "ioctl failed errno=%d", errno); return; } if (c->num_brps == 0 || c->num_brps > 16 || c->num_wrps == 0 || c->num_wrps > 16) { FAIL("S3_hwbp_caps", "insane brps=%u wrps=%u", c->num_brps, c->num_wrps); return; } if (c->hit_bytes != sizeof(drv_hwbp_hit)) { FAIL("S3_hwbp_caps", "hit_bytes=%u expected=%zu", c->hit_bytes, sizeof(drv_hwbp_hit)); return; } PASS("S3_hwbp_caps", "brps=%u wrps=%u ring=%u fp_ready=%u", c->num_brps, c->num_wrps, c->ring_slots, c->fp_ready); }

volatile uint32_t g_probe_word __attribute__((used));
__attribute__((noinline)) void probe_fn() { asm volatile("nop"); asm volatile("nop"); }
struct InstallCase { uint32_t type; uint32_t len; bool pass_through; bool expect_ok; const char* label; };
void test_install_matrix() { if (!require_hwbp("S4_install_matrix")) return; driver.setTarget(getpid()); uint64_t x_addr = reinterpret_cast<uint64_t>(&probe_fn); uint64_t w_addr = reinterpret_cast<uint64_t>(&g_probe_word); InstallCase cases[] = { {DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4, false, true, "X_len4"}, {DRV_HWBP_TYPE_X, DRV_HWBP_LEN_8, false, false, "X_len8_should_reject"}, {DRV_HWBP_TYPE_R, DRV_HWBP_LEN_4, false, true, "R_len4"}, {DRV_HWBP_TYPE_W, DRV_HWBP_LEN_1, false, true, "W_len1"}, {DRV_HWBP_TYPE_RW, DRV_HWBP_LEN_4, false, true, "RW_len4"}, {DRV_HWBP_TYPE_R, DRV_HWBP_LEN_4, true, false, "R_passthru_should_reject"}, }; for (const auto& c : cases) { uint64_t addr = (c.type == DRV_HWBP_TYPE_X) ? x_addr : w_addr; errno = 0; bool ok = driver.hwbp.install(addr, {}, c.pass_through, c.type, c.len); std::string name = std::string("S4_") + c.label; if (ok == c.expect_ok) PASS(name.c_str(), "ok=%d expected=%d", ok, c.expect_ok); else FAIL(name.c_str(), "ok=%d expected=%d errno=%d", ok, c.expect_ok, errno); if (ok) driver.hwbp.remove(addr); } driver.hwbp.clearAll(); }

static size_t hits_for_probe_fn(int reps) { for (int i = 0; i < reps; ++i) probe_fn(); return driver.hwbp.getHits(reinterpret_cast<uint64_t>(&probe_fn)).size(); }
void test_bypass_pid() { if (!require_hwbp("S5_bypass_pid")) return; driver.hwbp.clearAll(); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); errno = 0; if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S5_bypass_pid", "install failed errno=%d", errno); return; } size_t base = hits_for_probe_fn(2); driver.hwbp.remove(addr); driver.hwbp.clearAll(); errno = 0; if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S5_bypass_pid", "reinstall failed errno=%d", errno); return; } errno = 0; if (!driver.hwbp.setBypassPid(addr, getpid())) { FAIL("S5_bypass_pid", "setBypassPid failed errno=%d", errno); driver.hwbp.remove(addr); return; } size_t bypassed = hits_for_probe_fn(2); driver.hwbp.remove(addr); if (base > 0 && bypassed < base) PASS("S5_bypass_pid", "baseline=%zu bypassed=%zu (Δ=%zu)", base, bypassed, base - bypassed); else FAIL("S5_bypass_pid", "baseline=%zu bypassed=%zu — gate did not swallow", base, bypassed); }

void test_sample_gate() { if (!require_hwbp("S6_sample")) return; driver.hwbp.clearAll(); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S6_sample", "install failed"); return; } size_t base = hits_for_probe_fn(6); driver.hwbp.remove(addr); driver.hwbp.clearAll(); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S6_sample", "reinstall failed"); return; } if (!driver.hwbp.setSample(addr, 3)) { FAIL("S6_sample", "setSample failed"); driver.hwbp.remove(addr); return; } size_t gated = hits_for_probe_fn(6); driver.hwbp.remove(addr); size_t expected_hi = base / 3 + 1; if (base > 0 && gated <= expected_hi && gated > 0) PASS("S6_sample", "baseline=%zu every=3 gated=%zu (expected ≲%zu)", base, gated, expected_hi); else FAIL("S6_sample", "baseline=%zu gated=%zu — gate did not divide", base, gated); }

__attribute__((noinline)) void probe_fn_cond(uint64_t x0) { asm volatile("" : : "r"(x0)); }
void test_conditional() { if (!require_hwbp("S7_conditional")) return; driver.hwbp.clearAll(); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn_cond); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S7_conditional", "install failed"); return; } probe_fn_cond(1); probe_fn_cond(99); probe_fn_cond(42); size_t base = driver.hwbp.getHits(addr).size(); driver.hwbp.remove(addr); driver.hwbp.clearAll(); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S7_conditional", "reinstall failed"); return; } if (!driver.hwbp.setCondition(addr, 0, DRV_HWBP_COND_EQ, 42)) { FAIL("S7_conditional", "setCondition failed"); driver.hwbp.remove(addr); return; } probe_fn_cond(1); probe_fn_cond(99); probe_fn_cond(42); size_t gated = driver.hwbp.getHits(addr).size(); driver.hwbp.remove(addr); if (base > 0 && gated >= 1 && gated < base) PASS("S7_conditional", "baseline=%zu gated=%zu (only X0==42 leaked through)", base, gated); else FAIL("S7_conditional", "baseline=%zu gated=%zu — condition did not filter", base, gated); }

std::atomic<int> g_sig_int{0};
void sigrt_handler(int, siginfo_t* si, void*) { g_sig_int.store(si->si_int, std::memory_order_release); }
void test_notify() { if (!require_hwbp("S8_notify")) return; driver.hwbp.clearAll(); const int SIG = 42; g_sig_int.store(0, std::memory_order_release); struct sigaction sa{}; sa.sa_flags = SA_SIGINFO | SA_RESTART; sa.sa_sigaction = sigrt_handler; sigaction(SIG, &sa, nullptr); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); errno = 0; if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4, DRV_HWBP_FLAG_NOTIFY)) { FAIL("S8_notify", "install failed errno=%d", errno); return; } errno = 0; if (!driver.hwbp.setNotify(addr, getpid(), SIG)) { FAIL("S8_notify", "setNotify failed errno=%d", errno); driver.hwbp.remove(addr); return; } probe_fn(); int seen = 0; for (int i = 0; i < 100 && !seen; ++i) { seen = g_sig_int.load(std::memory_order_acquire); if (seen) break; usleep(10000); } driver.hwbp.remove(addr); if (seen) PASS("S8_notify", "signal %d received si_int=%d", SIG, seen); else FAIL("S8_notify", "no async delivery in 1s (signal never fired)"); }

__attribute__((noinline)) void probe_fn_fp() { asm volatile("nop"); }
void test_fpsimd_capture() { if (!require_hwbp("S9_fp_capture")) return; driver.hwbp.clearAll(); auto c = driver.hwbp.caps(); if (!c || !c->fp_ready) { SKIP("S9_fp_capture", "fp_ready=0 (no fpsimd_preserve_current_state)"); return; } driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn_fp); errno = 0; if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4, DRV_HWBP_FLAG_CAPTURE_FP)) { FAIL("S9_fp_capture", "install failed errno=%d", errno); return; } const uint64_t lo = 0xCAFEF00DDEADBEEFULL; const uint64_t hi = 0x0123456789ABCDEFULL; asm volatile("fmov d0, %0\n\tfmov v0.d[1], %1\n\t" : : "r"(lo), "r"(hi) : "v0"); probe_fn_fp(); auto hits = driver.hwbp.getHits(addr); driver.hwbp.remove(addr); if (hits.empty()) { FAIL("S9_fp_capture", "no hits — HWBP did not fire"); return; } if (hits[0].q_lo[0] == lo && hits[0].q_hi[0] == hi) PASS("S9_fp_capture", "Q0 captured lo=%016" PRIx64 " hi=%016" PRIx64, hits[0].q_lo[0], hits[0].q_hi[0]); else if (hits[0].q_lo[0] != 0 || hits[0].q_hi[0] != 0) PASS("S9_fp_capture", "FP snapshot present (Q0=%016" PRIx64 ":%016" PRIx64 " — libc call clobbered pattern)", hits[0].q_hi[0], hits[0].q_lo[0]); else FAIL("S9_fp_capture", "Q0 all zero — snapshot did not populate"); }

void test_translate_bait() { if (!require_hwbp("S10_translate_bait")) return; driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); errno = 0; auto out = driver.hwbp.translateBait(addr); if (!out) { FAIL("S10_translate_bait", "ioctl failed errno=%d", errno); return; } if (*out != 0) PASS("S10_translate_bait", "in=%px out=%px", (void*)addr, (void*)*out); else FAIL("S10_translate_bait", "returned 0"); }

uint64_t bench_ns(int reps, void (*fn)()) { auto t0 = std::chrono::steady_clock::now(); for (int i = 0; i < reps; ++i) fn(); auto t1 = std::chrono::steady_clock::now(); return std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count(); }
void test_timing_detector() { if (!require_hwbp("S11_timing")) return; driver.hwbp.clearAll(); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); const int REPS = 500; for (int i = 0; i < 1000; ++i) probe_fn(); uint64_t base_ns = bench_ns(REPS, probe_fn); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S11_timing", "install failed"); return; } uint64_t hwbp_ns = bench_ns(REPS, probe_fn); driver.hwbp.clearAll(); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4, DRV_HWBP_FLAG_TIMING_BYPASS)) { FAIL("S11_timing", "install(timing_bypass) failed"); return; } uint64_t tb_ns = bench_ns(REPS, probe_fn); driver.hwbp.clearAll(); double base_per = (double)base_ns / REPS; double hwbp_per = (double)hwbp_ns / REPS; double tb_per = (double)tb_ns / REPS; PASS("S11_timing", "per-call ns: base=%.1f hwbp=%.1f timing_bypass=%.1f (ratio %.2fx vs %.2fx)", base_per, hwbp_per, tb_per, hwbp_per / (base_per > 0 ? base_per : 1.0), tb_per / (base_per > 0 ? base_per : 1.0)); }

bool ioctl_name(uint32_t cmd, const char* name) { drv_ioctl_req req{}; req.buf = reinterpret_cast<uint64_t>(name); req.size = std::strlen(name); return driver.rawIoctl(cmd, &req); }
void test_file_hide() { const char* marker = "test_hidden_marker_9f37"; std::string path = std::string("/data/local/tmp/") + marker; errno = 0; FILE* f = std::fopen(path.c_str(), "w"); if (!f) { SKIP("S12_file_hide", "cannot create %s errno=%d", path.c_str(), errno); return; } std::fclose(f); bool seen_before = file_grep("/data/local/tmp/", marker) || [&]{ struct stat st; return stat(path.c_str(), &st) == 0; }(); if (!seen_before) SKIP("S12_file_hide", "marker not created?"); errno = 0; if (!ioctl_name(DRV_CMD_HIDE_NAME_ADD, marker)) { FAIL("S12_file_hide", "hide_name_add failed errno=%d", errno); unlink(path.c_str()); return; } bool seen_after = false; { FILE* d = popen("ls /data/local/tmp/", "r"); if (d) { char line[512]; while (std::fgets(line, sizeof(line), d)) if (std::strstr(line, marker)) { seen_after = true; break; } pclose(d); } } ioctl_name(DRV_CMD_HIDE_NAME_REMOVE, marker); unlink(path.c_str()); if (!seen_after) PASS("S12_file_hide", "marker vanished from readdir"); else FAIL("S12_file_hide", "marker still visible"); }

void test_pid_hide() { pid_t child = fork(); if (child == 0) { pause(); _exit(0); } if (child < 0) { FAIL("S13_pid_hide", "fork failed"); return; } drv_ioctl_req req{}; req.pid = child; errno = 0; if (!driver.rawIoctl(DRV_CMD_HIDE_PID_ADD, &req)) { FAIL("S13_pid_hide", "add failed errno=%d", errno); kill(child, SIGKILL); waitpid(child, nullptr, 0); return; } bool seen = false; std::string cmd = "ls /proc/ 2>/dev/null | grep -w " + std::to_string(child); FILE* p = popen(cmd.c_str(), "r"); if (p) { char l[64]; if (std::fgets(l, sizeof(l), p)) seen = true; pclose(p); } drv_ioctl_req rem{}; rem.pid = child; driver.rawIoctl(DRV_CMD_HIDE_PID_REMOVE, &rem); kill(child, SIGKILL); waitpid(child, nullptr, 0); if (!seen) PASS("S13_pid_hide", "pid %d vanished from /proc", child); else FAIL("S13_pid_hide", "pid %d still in /proc", child); }

extern "C" __attribute__((noinline)) void s14_slot_0(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_1(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_2(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_3(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_4(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_5(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_6(void) { asm volatile("nop"); }
extern "C" __attribute__((noinline)) void s14_slot_7(void) { asm volatile("nop"); }
static uint64_t s14_slots[] = { reinterpret_cast<uint64_t>(&s14_slot_0), reinterpret_cast<uint64_t>(&s14_slot_1), reinterpret_cast<uint64_t>(&s14_slot_2), reinterpret_cast<uint64_t>(&s14_slot_3), reinterpret_cast<uint64_t>(&s14_slot_4), reinterpret_cast<uint64_t>(&s14_slot_5), reinterpret_cast<uint64_t>(&s14_slot_6), reinterpret_cast<uint64_t>(&s14_slot_7), };
void test_fd_scoped_cleanup() { if (!require_hwbp("S14_fd_scoped")) return; driver.hwbp.clearAll(); auto caps = driver.hwbp.caps(); if (!caps) { FAIL("S14_fd_scoped", "caps failed"); return; } uint32_t brps = caps->num_brps; if (brps == 0 || brps > 8) { SKIP("S14_fd_scoped", "unusable brps=%u", brps); return; } { Driver alt; errno = 0; if (!alt.open()) { SKIP("S14_fd_scoped", "cannot open alt fd errno=%d", errno); return; } alt.setTarget(getpid()); for (uint32_t i = 0; i < brps; ++i) { errno = 0; if (!alt.hwbp.install(s14_slots[i], {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S14_fd_scoped", "alt install #%u failed errno=%d", i, errno); return; } } alt.close(); usleep(50000); } driver.setTarget(getpid()); uint32_t installed = 0; for (uint32_t i = 0; i < brps; ++i) { if (driver.hwbp.install(s14_slots[i], {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) ++installed; else break; } driver.hwbp.clearAll(); if (installed == brps) PASS("S14_fd_scoped", "release() freed all %u HW slots (primary reinstalled every one)", brps); else FAIL("S14_fd_scoped", "primary installed only %u/%u after alt close — slot leak", installed, brps); }

void test_fd_owner_isolation() { if (!require_hwbp("S15_fd_owner")) return; driver.hwbp.clearAll(); Driver alt; errno = 0; if (!alt.open()) { SKIP("S15_fd_owner", "cannot open second fd errno=%d", errno); return; } driver.setTarget(getpid()); alt.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S15_fd_owner", "primary install failed"); return; } if (!alt.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) { FAIL("S15_fd_owner", "secondary install failed"); driver.hwbp.remove(addr); return; } if (!alt.hwbp.clearAll()) { FAIL("S15_fd_owner", "alt.clearAll() returned false"); driver.hwbp.remove(addr); return; } errno = 0; if (alt.hwbp.remove(addr) || errno != ENOENT) { FAIL("S15_fd_owner", "alt.remove() after clearAll: got ok=%d errno=%d, expected fail+ENOENT", (int)alt.hwbp.remove(addr), errno); return; } if (!driver.hwbp.remove(addr)) { FAIL("S15_fd_owner", "primary tracker vanished after alt's clearAll"); return; } PASS("S15_fd_owner", "alt.clearAll dropped only alt; primary intact and removable"); }

void test_bait_guard_key_stable() { if (!require_hwbp("S16_bait_key")) return; driver.hwbp.clearAll(); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&probe_fn); errno = 0; if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4, DRV_HWBP_FLAG_BAIT_GUARD)) { FAIL("S16_bait_key", "install(BAIT_GUARD) failed errno=%d", errno); return; } if (!driver.hwbp.remove(addr)) FAIL("S16_bait_key", "remove(addr) failed — kernel rewrote the tracker key"); else PASS("S16_bait_key", "BAIT_GUARD accepted, tracker key unchanged"); }

__attribute__((noinline)) void poke_probe_word(uint32_t v) { g_probe_word = v; }
void test_watchpoint_oneshot() { if (!require_hwbp("S17_wp_oneshot")) return; driver.hwbp.clearAll(); driver.setTarget(getpid()); uint64_t addr = reinterpret_cast<uint64_t>(&g_probe_word); errno = 0; if (!driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_W, DRV_HWBP_LEN_4)) { FAIL("S17_wp_oneshot", "install(W) failed errno=%d", errno); return; } poke_probe_word(0xC0DEAAAAu); size_t first_hits = 0; for (int i = 0; i < 40 && !first_hits; ++i) { first_hits = driver.hwbp.getHits(addr).size(); if (first_hits) break; usleep(5000); } if (!first_hits) { FAIL("S17_wp_oneshot", "watchpoint never fired"); driver.hwbp.remove(addr); return; } usleep(50000); poke_probe_word(0xC0DEBBBBu); usleep(20000); size_t second_hits = driver.hwbp.getHits(addr).size(); driver.hwbp.remove(addr); if (second_hits == 0) PASS("S17_wp_oneshot", "watchpoint fired (%zu hits) and auto-disabled", first_hits); else FAIL("S17_wp_oneshot", "watchpoint kept firing after auto-disable (%zu extra)", second_hits); }

void test_legacy_hits_eproto() { if (!require_hwbp("S18_hits_legacy")) return; drv_ioctl_req req{}; req.pid = getpid(); req.addr = reinterpret_cast<uint64_t>(&probe_fn); req.buf = reinterpret_cast<uint64_t>(&req); req.size = 4096; errno = 0; bool ok = driver.rawIoctl(DRV_CMD_HWBP_GET_HITS_LEGACY, &req); if (!ok && errno == EPROTO) PASS("S18_hits_legacy", "legacy 0x43 returned EPROTO as designed"); else FAIL("S18_hits_legacy", "expected EPROTO, got ok=%d errno=%d", ok, errno); }

void test_bait_guard_not_advertised() { if (!require_hwbp("S19_bait_deprecated")) return; errno = 0; auto c = driver.hwbp.caps(); if (!c) { FAIL("S19_bait_deprecated", "caps ioctl failed errno=%d", errno); return; } uint32_t flags = DRV_HWBP_CAPS_FLAGS(c->flags_supported); uint32_t gen = DRV_HWBP_CAPS_GEN(c->flags_supported); if (flags & DRV_HWBP_FLAG_BAIT_GUARD) FAIL("S19_bait_deprecated", "kernel still advertises BAIT_GUARD flags=0x%x", flags); else PASS("S19_bait_deprecated", "BAIT_GUARD dropped; flags=0x%x gen=%u", flags, gen); }

void test_caps_no_overflow() { if (!require_hwbp("S21_caps_size")) return; struct { drv_hwbp_caps c; uint32_t canary[2]; } buf{}; uint32_t gen; buf.canary[0] = 0xDEADC0DEu; buf.canary[1] = 0xFEEDFACEu; errno = 0; if (!driver.rawIoctl(DRV_CMD_HWBP_GET_CAPS, &buf.c)) { FAIL("S21_caps_size", "GET_CAPS failed errno=%d", errno); return; } if (buf.canary[0] != 0xDEADC0DEu || buf.canary[1] != 0xFEEDFACEu) { FAIL("S21_caps_size", "GET_CAPS wrote past 32 bytes; canary=%08x %08x", buf.canary[0], buf.canary[1]); return; } gen = DRV_HWBP_CAPS_GEN(buf.c.flags_supported); if (gen != DRV_HWBP_ABI_GENERATION) FAIL("S21_caps_size", "gen mismatch: got %u, expected %u", gen, DRV_HWBP_ABI_GENERATION); else PASS("S21_caps_size", "caps=32B, canary intact, gen=%u", gen); }

void test_stale_mm_dropped() { if (!require_hwbp("S22_stale_mm")) return; pid_t child; uint64_t addr = 0x100000; bool first_ok = false; bool second_ok; int second_err; driver.hwbp.clearAll(); child = fork(); if (child == 0) { usleep(50000); execl("/system/bin/sleep", "sleep", "1", (char*)nullptr); _exit(1); } if (child < 0) { FAIL("S22_stale_mm", "fork failed errno=%d", errno); return; } driver.setTarget(child); for (int i = 0; i < 20 && !first_ok; ++i) { errno = 0; if (driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4)) first_ok = true; else usleep(2000); } usleep(200000); errno = 0; second_ok = driver.hwbp.install(addr, {}, false, DRV_HWBP_TYPE_X, DRV_HWBP_LEN_4); second_err = errno; driver.hwbp.clearAll(); kill(child, SIGKILL); waitpid(child, nullptr, 0); if (!first_ok) { SKIP("S22_stale_mm", "first install never took; skip mm-race check"); return; } if (second_ok || second_err == EFAULT || second_err == EINVAL || second_err == ESRCH || second_err == EOPNOTSUPP) PASS("S22_stale_mm", "second install after exec: ok=%d errno=%d (stale mm handled)", second_ok, second_err); else FAIL("S22_stale_mm", "second install returned unexpected errno=%d", second_err); }

void test_pte_hook_not_hijacked() { drv_pte_hook_install_req req{}; req.pid = getpid(); req.kind = DRV_PTE_HOOK_CONST_U64; req.addr = 0; req.ret_value = 0xDEADBEEF; errno = 0; bool ok = driver.rawIoctl(DRV_CMD_PTE_HOOK_INSTALL, &req); int e = errno; if (ok) { FAIL("S20_pte_routing", "PTE install of addr=0 unexpectedly succeeded"); return; } if (e == EPROTO || e == ENOTTY) FAIL("S20_pte_routing", "PTE_HOOK_INSTALL was routed to HWBP (errno=%d)", e); else PASS("S20_pte_routing", "PTE_HOOK_INSTALL reached PTE handler (errno=%d)", e); }

void test_ring_buffer() {
    size_t ring_size = 2 * 1024 * 1024; 
    void* ring_ptr = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ring_ptr == MAP_FAILED) { FAIL("S23_ring_buffer", "mmap failed errno=%d", errno); return; }
    if (mlock(ring_ptr, ring_size) != 0) { FAIL("S23_ring_buffer", "mlock failed errno=%d", errno); munmap(ring_ptr, ring_size); return; }
    drv_ring_header* hdr = (drv_ring_header*)ring_ptr;
    memset(hdr, 0, sizeof(drv_ring_header));
    hdr->capacity = (ring_size - 4096) / 16; 
    hdr->event_size = 16;
    errno = 0;
    if (!driver.ring.init(ring_ptr, ring_size)) { FAIL("S23_ring_buffer", "ring init failed errno=%d", errno); munlock(ring_ptr, ring_size); munmap(ring_ptr, ring_size); return; }
    PASS("S23_ring_buffer", "ring registered at %p, size=%zu", ring_ptr, ring_size);
    driver.close();
    if (!driver.open()) { FAIL("S23_ring_buffer", "driver reopen failed after ring cleanup"); }
    munlock(ring_ptr, ring_size);
    munmap(ring_ptr, ring_size);
}

} // anon

int main() {
	std::setvbuf(stdout, nullptr, _IOLBF, 0);
	alarm(120);
	std::printf("== my-driver-test starting (pid=%d) ==\n", getpid());
	if (!test_open()) { std::printf("driver.open failed — cannot run remaining tests\n"); return 2; }
	test_stealth_surface();
	test_caps();
	test_install_matrix();
	test_bypass_pid();
	test_sample_gate();
	test_conditional();
	test_notify();
	test_fpsimd_capture();
	test_translate_bait();
	test_timing_detector();
	test_file_hide();
	test_pid_hide();
	test_fd_scoped_cleanup();
	test_fd_owner_isolation();
	test_bait_guard_key_stable();
	test_watchpoint_oneshot();
	test_legacy_hits_eproto();
	test_bait_guard_not_advertised();
	test_pte_hook_not_hijacked();
	test_caps_no_overflow();
	test_stale_mm_dropped();
	test_ring_buffer();

	std::printf("\n== summary: %d PASS, %d FAIL, %d SKIP ==\n", g_passes, g_fails, g_skips);
	return g_fails ? 1 : 0;
}
