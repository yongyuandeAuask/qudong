#include "wx_shadow_api.h"
#include "Driver.h"

bool WxShadowApi::setBp(pid_t pid, uint64_t addr, const void* cfg) {
    drv_wxshadow_req req{};
    req.pid = pid; req.addr = addr; req.buf = reinterpret_cast<uint64_t>(cfg);
    return m_d.rawIoctl(DRV_CMD_WX_SET_BP, &req);
}

bool WxShadowApi::delBp(pid_t pid, uint64_t addr) {
    drv_wxshadow_req req{};
    req.pid = pid; req.addr = addr;
    return m_d.rawIoctl(DRV_CMD_WX_DEL_BP, &req);
}

bool WxShadowApi::patch(pid_t pid, uint64_t addr, const void* cfg) {
    drv_wxshadow_req req{};
    req.pid = pid; req.addr = addr; req.buf = reinterpret_cast<uint64_t>(cfg);
    return m_d.rawIoctl(DRV_CMD_WX_PATCH, &req);
}

bool WxShadowApi::release(pid_t pid, uint64_t addr) {
    drv_wxshadow_req req{};
    req.pid = pid; req.addr = addr;
    return m_d.rawIoctl(DRV_CMD_WX_RELEASE, &req);
}

bool WxShadowApi::getState(pid_t pid, void* info) {
    drv_wxshadow_req req{};
    req.pid = pid; req.buf = reinterpret_cast<uint64_t>(info);
    return m_d.rawIoctl(DRV_CMD_WX_GET_STATE, &req);
}
