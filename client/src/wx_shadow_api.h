#pragma once
#include <cstdint>
#include <cstddef>
#include "driver/uapi.h"

class Driver;

class WxShadowApi {
public:
    WxShadowApi(Driver& d) : m_d(d) {}
    bool setBp(pid_t pid, uint64_t addr, const void* cfg);
    bool delBp(pid_t pid, uint64_t addr);
    bool patch(pid_t pid, uint64_t addr, const void* cfg);
    bool release(pid_t pid, uint64_t addr);
    bool getState(pid_t pid, void* info);
private:
    Driver& m_d;
};
