#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

// 必须与 KPM hello.c 中的结构体逐字节完全一致
#define SLOT_DATA  232
#define SLOT_CNT   60
#define RING_PAGES 4
#define RING_SIZE  (RING_PAGES * 4096)
#define RING_IOC_META 0x5351

// 内存屏障宏 (ARM64)
#define smp_wmb() asm volatile("dsb st" ::: "memory")
#define smp_rmb() asm volatile("dsb ld" ::: "memory")

struct Slot {
    volatile uint32_t op;      // 0=READ 1=WRITE
    volatile uint32_t pid;
    volatile uint64_t vaddr;
    volatile uint32_t len;
    volatile uint32_t status;  // 0=pending 1=ok 2=fail
    uint8_t data[SLOT_DATA];
};

struct Ring {
    volatile uint32_t head;
    volatile uint32_t tail;
    volatile uint32_t req_seq;
    volatile uint32_t done_seq;
    volatile uint32_t slot_cnt;
    volatile uint32_t slot_size;
    Slot slots[SLOT_CNT];
};

// 测试用的内存区域
static char g_read_buf[64]  = "THIS_IS_KPM_READ_TEST_DATA_1234567890";
static char g_write_buf[64] = { 0 };

int main(int argc, char** argv) {
    printf("[KPM Client] Starting Zero-Syscall Ring Test...\n");

    /* === 建立期 1: open === */
    int fd = open("/proc/stealth_ring", O_RDWR);
    if (fd < 0) {
        perror("[FAIL] open /proc/stealth_ring (KPM loaded?)");
        return 1;
    }

    /* === 建立期 2: ioctl 取元信息 === */
    unsigned long meta[4] = {0};
    if (ioctl(fd, RING_IOC_META, meta) != 0) {
        perror("[FAIL] ioctl RING_IOC_META");
        close(fd);
        return 1;
    }

    /* === 建立期 3: mmap 一次拿共享页 === */
    Ring* ring = (Ring*)mmap(nullptr, RING_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        perror("[FAIL] mmap");
        close(fd);
        return 1;
    }

    /* === 建立期 4: close (通道与 fd 解耦) === */
    close(fd);
    printf("[PASS] Channel up. Ring mapped at %p, slot_size=%lu\n", (void*)ring, meta[2]);

    /* ==========================================
       === 运行期：零 syscall 批量下发请求测试 ===
       ========================================== */
    
    unsigned base_head = ring->head;
    
    // 1. 构造 READ 请求槽
    Slot* s_read = &ring->slots[base_head % SLOT_CNT];
    s_read->op = 0; // READ
    s_read->pid = getpid();
    s_read->vaddr = (uint64_t)g_read_buf;
    s_read->len = 32;
    s_read->status = 0;

    // 2. 构造 WRITE 请求槽
    Slot* s_write = &ring->slots[(base_head + 1) % SLOT_CNT];
    s_write->op = 1; // WRITE
    s_write->pid = getpid();
    s_write->vaddr = (uint64_t)g_write_buf;
    s_write->len = 16;
    memcpy((void*)s_write->data, "MAGIC_FROM_KPM", 16); // 预填数据让内核写入目标
    s_write->status = 0;

    // 3. 屏障并批量推进 head (2个请求)
    smp_wmb();
    ring->head = base_head + 2;
    ring->req_seq++;
    smp_wmb();

    printf("[INFO] Submitted 2 requests (1 READ, 1 WRITE). Waiting for kthread...\n");

    // 4. 轮询等待内核 kthread 处理完毕 (通过 seq 确认)
    while (ring->done_seq != ring->req_seq) {
        smp_rmb();
        usleep(100); 
    }

    // 5. 校验结果
    printf("\n--- Results ---\n");
    if (s_read->status == 1) {
        printf("[PASS] READ  status=1, data=\"%s\"\n", s_read->data);
    } else {
        printf("[FAIL] READ  status=%u (Expected 1)\n", s_read->status);
    }

    if (s_write->status == 1) {
        printf("[PASS] WRITE status=1, g_write_buf=\"%s\"\n", g_write_buf);
    } else {
        printf("[FAIL] WRITE status=%u (Expected 1)\n", s_write->status);
    }

    // 6. 清理映射
    munmap(ring, RING_SIZE);
    printf("\n[KPM Client] Test finished.\n");

    return 0;
}
