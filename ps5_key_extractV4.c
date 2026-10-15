/*
 * ps5_key_extractV4.c — Enhanced PUP key extractor with CCP intercept
 *
 * V4 adds to V3:
 *   Approach 6: CCP Queue Snoop — monitor CCP command submissions during decrypt
 *   Approach 7: Symbol Resolve  — find crypto functions via kernel_dynlib_dlsym
 *   Approach 8: CCP PASSTHROUGH — copy key from private SB slot to system memory
 *   Approach 9: Decrypt Oracle  — feed real PUP data and capture decrypted output
 *
 * Build: prospero-clang from ps5-payload-dev SDK
 *   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
 *   $PS5_PAYLOAD_SDK/bin/prospero-clang -o ps5_key_extract.elf ps5_key_extractV4.c
 *
 * Usage:
 *   ./ps5_key_extract                        — full scan (approaches 1-7)
 *   ./ps5_key_extract -a 0xFFFF... [-s N]    — targeted address read (approach 5)
 *   ./ps5_key_extract -p <slot> [-q <queue>] — PASSTHROUGH extract from SB slot
 *   ./ps5_key_extract -d                     — decrypt oracle (/data/pup_header.bin)
 *
 * Approaches 1-7 are READ-ONLY (safe).
 * Approach 8 WRITES to CCP hardware (aggressive). Approach 9 is read-only.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---------- kernel R/W primitives (ps5-payload-dev SDK) ---------- */
#include <ps5/kernel.h>

static inline uint64_t kread64(uint64_t kaddr) {
    return kernel_getlong((intptr_t)kaddr);
}
static inline uint32_t kread32(uint64_t kaddr) {
    return kernel_getint((intptr_t)kaddr);
}
static inline void kwrite64(uint64_t kaddr, uint64_t val) {
    kernel_setlong((intptr_t)kaddr, val);
}
static inline void kwrite32(uint64_t kaddr, uint32_t val) {
    kernel_setint((intptr_t)kaddr, val);
}

/* ---------- output format (v3) ---------- */
#define DUMP_MAGIC          0x505550444D50ULL  /* "PUPDMP\0\0" */
#define DUMP_VERSION        3

#define SECTION_LSB           0x01
#define SECTION_IOCTL         0x02
#define SECTION_SNAP_PRE      0x03
#define SECTION_SNAP_POST     0x04
#define SECTION_MEMSCAN       0x05
#define SECTION_CDEVSW        0x06
#define SECTION_CCP_REGS      0x07
#define SECTION_ADDR_READ     0x08
#define SECTION_HANDLER_OPEN  0x09
#define SECTION_HANDLER_CLOSE 0x0A
#define SECTION_CCP_CMD       0x0B
#define SECTION_SYMRESOLVE    0x0C
#define SECTION_PASSTHROUGH   0x0D
#define SECTION_ORACLE_IN     0x0E
#define SECTION_ORACLE_OUT    0x0F

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t section_count;
} __attribute__((packed)) dump_header_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t offset;
    uint32_t reserved;
} __attribute__((packed)) section_header_t;

/* ---------- AMD CCP v5 constants ---------- */
#define CCP_QUEUE_MMIO_BASE  0x3001000
#define CCP_QUEUE_STRIDE     0x1000
#define CCP_NUM_QUEUES       5

#define CCP_REG_CONTROL      0x00
#define CCP_REG_TAIL_LO      0x04
#define CCP_REG_HEAD_LO      0x08
#define CCP_REG_INT_ENABLE   0x0C
#define CCP_REG_INT_STATUS   0x10
#define CCP_REG_STATUS       0x14
#define CCP_PUBLIC_MASK_LO   0x18
#define CCP_PUBLIC_MASK_HI   0x1C
#define CCP_PRIVATE_MASK_LO  0x20
#define CCP_PRIVATE_MASK_HI  0x24
#define CCP_REG_STATUS2      0x28

#define CCP_QUEUE_REG_COUNT  11
#define CCP_QUEUE_REG_SIZE   (CCP_QUEUE_REG_COUNT * 4)

/* CCP v5 command descriptor */
#define CCP_DESC_SIZE  32

typedef struct {
    uint32_t dw[8];
} __attribute__((packed)) ccp5_desc_t;

/* CCP v5 descriptor field extraction */
#define CCP_DESC_ENGINE(d)   (((d)->dw[0] >> 20) & 0xF)
#define CCP_DESC_FUNCTION(d) (((d)->dw[0] >> 5) & 0x7FFF)
#define CCP_DESC_EOM(d)      (((d)->dw[0] >> 4) & 1)
#define CCP_DESC_INIT(d)     (((d)->dw[0] >> 3) & 1)
#define CCP_DESC_LENGTH(d)   ((d)->dw[1])
#define CCP_DESC_SRC_LO(d)   ((d)->dw[2])
#define CCP_DESC_SRC_MEM(d)  (((d)->dw[3] >> 16) & 3)
#define CCP_DESC_DST_LO(d)   ((d)->dw[4])
#define CCP_DESC_DST_MEM(d)  (((d)->dw[5] >> 16) & 3)
#define CCP_DESC_KEY_LO(d)   ((d)->dw[6])
#define CCP_DESC_KEY_MEM(d)  (((d)->dw[7] >> 16) & 3)

/* Engine IDs */
#define CCP_ENGINE_AES         0
#define CCP_ENGINE_XTS_AES     1
#define CCP_ENGINE_SHA         2
#define CCP_ENGINE_RSA         3
#define CCP_ENGINE_PASSTHROUGH 5
#define CCP_ENGINE_ZLIB        6

/* Memory types */
#define CCP_MEMTYPE_SYSTEM  0
#define CCP_MEMTYPE_SB      1
#define CCP_MEMTYPE_LOCAL   2

/* AES function field bits (within the 15-bit function) */
#define CCP_AES_MODE_MASK   0x000F  /* bits [3:0]: ECB=0,CBC=1,OFB=2,CFB=3,CTR=4 */
#define CCP_AES_SIZE_MASK   0x0030  /* bits [5:4]: 128=0,192=1,256=2 */
#define CCP_AES_DECRYPT     0x0040  /* bit 6: decrypt */
#define CCP_AES_KEY_SB      0x0080  /* bit 7: key from SB (vs from memory) */

/* LSB geometry */
#define LSB_OFFSET_A         0x8000
#define LSB_OFFSET_B         0x10000
#define LSB_OFFSET_C         0x4000
#define LSB_COUNT            8
#define SLOTS_PER_LSB        16
#define SLOT_SIZE            32
#define LSB_TOTAL_SIZE       (LSB_COUNT * SLOTS_PER_LSB * SLOT_SIZE)

/* ---------- PUP ioctl constants ---------- */
#define PUP_DEVICE_PATH      "/dev/pup_update0"

#define PUP_IOCTL_VERIFY_BLS      0xC0104401
#define PUP_IOCTL_DECRYPT_HEADER  0xC0184402
#define PUP_IOCTL_VERIFY_ADDSIGN  0xC0184403
#define PUP_IOCTL_VERIFY_WATER    0xC0184404
#define PUP_IOCTL_DECRYPT_SEG     0xC0184405
#define PUP_IOCTL_DECRYPT_BLOCK   0xC0284406

/* ---------- kernel constants ---------- */
#define CDEVSW_D_VERSION     0x00
#define CDEVSW_D_FLAGS       0x04
#define CDEVSW_D_NAME        0x08
#define CDEVSW_D_OPEN        0x10
#define CDEVSW_D_CLOSE       0x18
#define CDEVSW_D_READ        0x20
#define CDEVSW_D_WRITE       0x28
#define CDEVSW_D_IOCTL       0x30
#define CDEVSW_D_POLL        0x38
#define CDEVSW_D_MMAP        0x40
#define CDEVSW_D_STRATEGY    0x48
#define CDEVSW_D_KQFILTER    0x58
#define CDEVSW_SIZE          0x80

#define HANDLER_DUMP_SIZE    (16 * 1024)

/* ---------- globals ---------- */
#define OUTPUT_MAX           (1024 * 1024)
static uint8_t  g_output[OUTPUT_MAX];
static uint32_t g_output_pos = 0;
static uint32_t g_section_count = 0;

#define MAX_SECTIONS 64
static section_header_t g_sections[MAX_SECTIONS];

/* CCP BAR candidates — tried by multiple approaches */
static const uint64_t g_bar_candidates[] = {
    0xE0100000ULL, 0xFED80000ULL, 0xFEC10000ULL, 0x03000000ULL
};
#define NUM_BAR_CANDIDATES (sizeof(g_bar_candidates)/sizeof(g_bar_candidates[0]))

/* ---------- output helpers ---------- */
static void output_begin(void) {
    g_output_pos = sizeof(dump_header_t) + sizeof(g_sections);
    g_section_count = 0;
    memset(g_output, 0, sizeof(g_output));
}

static void output_add_section(uint32_t type, const void *data, uint32_t size) {
    if (g_section_count >= MAX_SECTIONS) return;
    if (g_output_pos + size > OUTPUT_MAX) return;

    g_sections[g_section_count].type = type;
    g_sections[g_section_count].size = size;
    g_sections[g_section_count].offset = g_output_pos;
    g_sections[g_section_count].reserved = 0;

    memcpy(g_output + g_output_pos, data, size);
    g_output_pos += size;
    g_section_count++;
}

static int output_write(const char *path) {
    dump_header_t hdr;
    hdr.magic = DUMP_MAGIC;
    hdr.version = DUMP_VERSION;
    hdr.section_count = g_section_count;

    memcpy(g_output, &hdr, sizeof(hdr));
    memcpy(g_output + sizeof(hdr), g_sections, sizeof(g_sections));

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("[!] Failed to open %s for writing\n", path);
        return -1;
    }
    write(fd, g_output, g_output_pos);
    close(fd);
    printf("[+] Wrote %u bytes to %s (%u sections)\n",
           g_output_pos, path, g_section_count);
    return 0;
}

static void hexdump(const char *label, const uint8_t *data, size_t len) {
    printf("[*] %s (%zu bytes):\n", label, len);
    size_t show = len > 256 ? 256 : len;
    for (size_t i = 0; i < show; i++) {
        if (i > 0 && (i % 16) == 0) printf("\n");
        if ((i % 16) == 0) printf("    %04zx: ", i);
        printf("%02x ", data[i]);
    }
    printf("\n");
    if (show < len)
        printf("    ... (%zu more bytes in dump)\n", len - show);
}

/* ---------- helper: open dmem ---------- */
static int open_dmem(void) {
    int fd = open("/dev/dmem0", O_RDWR);
    if (fd < 0) fd = open("/dev/mem", O_RDWR);
    return fd;
}

/* ---------- helper: get kernel scan base ---------- */
static uint64_t get_kernel_base(void) {
    uint64_t base = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
    if (base >= 0xFFFFFFFF80000000ULL) {
        printf("[+] SDK kernel text base: 0x%llx\n", (unsigned long long)base);
        return base;
    }
    printf("[!] SDK kernel base invalid (0x%llx), using fallback\n",
           (unsigned long long)base);
    return 0xFFFFFFFF82200000ULL;
}

/* ================================================================
 * APPROACH 1: CCP LSB Key Slot Dump + Queue Register Dump
 * (unchanged from V3)
 * ================================================================ */
static int approach1_ccp_lsb_dump(void) {
    printf("\n=== APPROACH 1: CCP LSB Key Slot Dump + Queue Registers ===\n");

    int dmem_fd = open_dmem();
    if (dmem_fd < 0) {
        printf("[!] Cannot open /dev/dmem0 or /dev/mem\n");
        return -1;
    }

    uint32_t lsb_offsets[] = { LSB_OFFSET_A, LSB_OFFSET_B, LSB_OFFSET_C };
    uint8_t  lsb_data[LSB_TOTAL_SIZE];
    int      found_any = 0;

    for (int b = 0; b < (int)NUM_BAR_CANDIDATES; b++) {
        uint64_t bar = g_bar_candidates[b];

        for (int lo = 0; lo < (int)(sizeof(lsb_offsets)/sizeof(lsb_offsets[0])); lo++) {
            uint64_t lsb_phys = bar + lsb_offsets[lo];
            printf("[*] Trying BAR 0x%llx + LSB offset 0x%x = 0x%llx\n",
                   (unsigned long long)bar, lsb_offsets[lo],
                   (unsigned long long)lsb_phys);

            void *mapped = mmap(NULL, LSB_TOTAL_SIZE, PROT_READ, MAP_SHARED,
                                dmem_fd, (off_t)lsb_phys);
            if (mapped == MAP_FAILED) continue;

            memcpy(lsb_data, mapped, LSB_TOTAL_SIZE);
            munmap(mapped, LSB_TOTAL_SIZE);

            int nonzero_count = 0;
            for (int slot = 0; slot < LSB_COUNT * SLOTS_PER_LSB; slot++) {
                uint8_t *s = &lsb_data[slot * SLOT_SIZE];
                int is_zero = 1;
                for (int j = 0; j < SLOT_SIZE; j++) {
                    if (s[j] != 0) { is_zero = 0; break; }
                }
                if (!is_zero) {
                    nonzero_count++;
                    printf("[+] Non-zero LSB slot %d (LSB %d, slot %d):\n",
                           slot, slot / SLOTS_PER_LSB, slot % SLOTS_PER_LSB);
                    hexdump("  slot data", s, SLOT_SIZE);
                }
            }

            if (nonzero_count > 0) {
                printf("[+] Found %d non-zero slots at BAR 0x%llx + 0x%x\n",
                       nonzero_count, (unsigned long long)bar, lsb_offsets[lo]);
                output_add_section(SECTION_LSB, lsb_data, LSB_TOTAL_SIZE);
                found_any = 1;
            }
        }

        uint8_t queue_regs[CCP_NUM_QUEUES * CCP_QUEUE_REG_SIZE];
        int got_regs = 0;
        memset(queue_regs, 0, sizeof(queue_regs));

        for (int q = 0; q < CCP_NUM_QUEUES; q++) {
            uint64_t queue_base = bar + CCP_QUEUE_MMIO_BASE + (q * CCP_QUEUE_STRIDE);
            void *qmap = mmap(NULL, 0x100, PROT_READ, MAP_SHARED,
                              dmem_fd, (off_t)queue_base);
            if (qmap == MAP_FAILED) continue;

            uint32_t *dst = (uint32_t *)&queue_regs[q * CCP_QUEUE_REG_SIZE];
            dst[0]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_CONTROL);
            dst[1]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_TAIL_LO);
            dst[2]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_HEAD_LO);
            dst[3]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_INT_ENABLE);
            dst[4]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_INT_STATUS);
            dst[5]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_STATUS);
            dst[6]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PUBLIC_MASK_LO);
            dst[7]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PUBLIC_MASK_HI);
            dst[8]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PRIVATE_MASK_LO);
            dst[9]  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PRIVATE_MASK_HI);
            dst[10] = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_STATUS2);
            munmap(qmap, 0x100);

            printf("[+] Queue %d: ctrl=0x%08x status=0x%08x "
                   "pub=0x%08x%08x priv=0x%08x%08x\n",
                   q, dst[0], dst[5], dst[7], dst[6], dst[9], dst[8]);
            got_regs = 1;
        }

        if (got_regs)
            output_add_section(SECTION_CCP_REGS, queue_regs, sizeof(queue_regs));
    }

    close(dmem_fd);
    return found_any ? 0 : -1;
}

/* ================================================================
 * APPROACH 2: EncryptService Full Handler Dump
 * IMPROVED: uses SDK KERNEL_ADDRESS_TEXT_BASE
 * ================================================================ */
static int approach2_ioctl_handler_scan(void) {
    printf("\n=== APPROACH 2: EncryptService Full Handler Dump ===\n");

    uint64_t kbase = get_kernel_base();
    const char *search_str = "pup_update";
    size_t search_len = strlen(search_str);

    size_t scan_size = 32 * 1024 * 1024;
    uint8_t *kbuf = (uint8_t *)malloc(scan_size);
    if (!kbuf) {
        printf("[!] malloc failed for kernel scan buffer\n");
        return -1;
    }

    /* Try SDK base first, then data segment, then fallback */
    uint64_t bases[] = {
        kbase,
        (uint64_t)KERNEL_ADDRESS_DATA_BASE,
        0xFFFFFFFF80000000ULL
    };

    for (int kb = 0; kb < 3; kb++) {
        uint64_t base = bases[kb];
        if (base < 0xFFFFFFFF80000000ULL) continue;

        printf("[*] Scanning kernel at base 0x%llx...\n", (unsigned long long)base);

        if (kernel_copyout(base, kbuf, scan_size) != 0) {
            printf("[!] kernel_copyout failed for base 0x%llx\n",
                   (unsigned long long)base);
            continue;
        }

        for (size_t i = 0; i < scan_size - search_len; i++) {
            if (memcmp(&kbuf[i], search_str, search_len) != 0) continue;
            if (kbuf[i + search_len] != '\0') continue;

            uint64_t str_kaddr = base + i;
            printf("[+] Found \"%s\" at kernel address 0x%llx\n",
                   search_str, (unsigned long long)str_kaddr);

            for (size_t j = 0; j < scan_size - 8; j += 8) {
                uint64_t val;
                memcpy(&val, &kbuf[j], 8);
                if (val != str_kaddr) continue;

                uint64_t ptr_kaddr = base + j;
                uint64_t cdevsw_base = ptr_kaddr - CDEVSW_D_NAME;

                printf("[+] Candidate cdevsw at 0x%llx\n",
                       (unsigned long long)cdevsw_base);

                uint64_t d_open  = kread64(cdevsw_base + CDEVSW_D_OPEN);
                uint64_t d_close = kread64(cdevsw_base + CDEVSW_D_CLOSE);
                uint64_t d_ioctl = kread64(cdevsw_base + CDEVSW_D_IOCTL);

                printf("[+] d_open=0x%llx  d_close=0x%llx  d_ioctl=0x%llx\n",
                       (unsigned long long)d_open,
                       (unsigned long long)d_close,
                       (unsigned long long)d_ioctl);

                if (d_ioctl < 0xFFFFFFFF80000000ULL) {
                    printf("[!] d_ioctl looks invalid, skipping\n");
                    continue;
                }

                uint8_t cdevsw_raw[CDEVSW_SIZE];
                if (kernel_copyout(cdevsw_base, cdevsw_raw, sizeof(cdevsw_raw)) == 0)
                    output_add_section(SECTION_CDEVSW, cdevsw_raw, sizeof(cdevsw_raw));

                uint8_t handler_code[HANDLER_DUMP_SIZE];
                if (kernel_copyout(d_ioctl, handler_code, sizeof(handler_code)) == 0) {
                    printf("[+] Dumped d_ioctl handler (%d bytes)\n", HANDLER_DUMP_SIZE);
                    output_add_section(SECTION_IOCTL, handler_code, sizeof(handler_code));
                }

                if (d_open >= 0xFFFFFFFF80000000ULL) {
                    uint8_t open_code[HANDLER_DUMP_SIZE];
                    if (kernel_copyout(d_open, open_code, sizeof(open_code)) == 0) {
                        printf("[+] Dumped d_open handler (%d bytes)\n", HANDLER_DUMP_SIZE);
                        output_add_section(SECTION_HANDLER_OPEN, open_code,
                                           sizeof(open_code));
                    }
                }

                if (d_close >= 0xFFFFFFFF80000000ULL) {
                    uint8_t close_code[HANDLER_DUMP_SIZE];
                    if (kernel_copyout(d_close, close_code, sizeof(close_code)) == 0) {
                        printf("[+] Dumped d_close handler (%d bytes)\n", HANDLER_DUMP_SIZE);
                        output_add_section(SECTION_HANDLER_CLOSE, close_code,
                                           sizeof(close_code));
                    }
                }

                free(kbuf);
                return 0;
            }
        }
    }

    free(kbuf);
    printf("[!] Could not locate pup_update cdevsw\n");
    return -1;
}

/* ================================================================
 * APPROACH 3: Instrumented PUP Decrypt (LSB snapshot)
 * (unchanged from V3)
 * ================================================================ */
static int approach3_instrumented_decrypt(void) {
    printf("\n=== APPROACH 3: Instrumented PUP Decrypt ===\n");

    int pup_fd = open(PUP_DEVICE_PATH, O_RDWR);
    if (pup_fd < 0) {
        printf("[!] Cannot open %s\n", PUP_DEVICE_PATH);
        return -1;
    }

    int dmem_fd = open_dmem();
    if (dmem_fd < 0) { close(pup_fd); return -1; }

    uint64_t lsb_phys = 0x03000000ULL + LSB_OFFSET_A;
    uint8_t pre_lsb[LSB_TOTAL_SIZE], post_lsb[LSB_TOTAL_SIZE];

    void *mapped = mmap(NULL, LSB_TOTAL_SIZE, PROT_READ, MAP_SHARED,
                        dmem_fd, (off_t)lsb_phys);
    if (mapped == MAP_FAILED) {
        printf("[!] Cannot map LSB region\n");
        close(dmem_fd); close(pup_fd); return -1;
    }

    memcpy(pre_lsb, mapped, LSB_TOTAL_SIZE);
    output_add_section(SECTION_SNAP_PRE, pre_lsb, LSB_TOTAL_SIZE);

    struct { void *buffer; size_t length; int type; } dh_args;
    uint8_t dummy_header[0x600];
    memset(dummy_header, 0, sizeof(dummy_header));
    dummy_header[0] = 0x54; dummy_header[1] = 0x14;
    dummy_header[2] = 0xF5; dummy_header[3] = 0xEE;
    dh_args.buffer = dummy_header;
    dh_args.length = sizeof(dummy_header);
    dh_args.type   = 1;

    printf("[*] Triggering DecryptHeader ioctl (type=1)...\n");
    int ret = ioctl(pup_fd, PUP_IOCTL_DECRYPT_HEADER, &dh_args);
    printf("[*] ioctl returned %d\n", ret);

    memcpy(post_lsb, mapped, LSB_TOTAL_SIZE);
    munmap(mapped, LSB_TOTAL_SIZE);
    output_add_section(SECTION_SNAP_POST, post_lsb, LSB_TOTAL_SIZE);

    int changes = 0;
    for (int slot = 0; slot < LSB_COUNT * SLOTS_PER_LSB; slot++) {
        if (memcmp(&pre_lsb[slot * SLOT_SIZE], &post_lsb[slot * SLOT_SIZE],
                   SLOT_SIZE) != 0) {
            printf("[+] LSB slot %d CHANGED during decrypt!\n", slot);
            hexdump("  after", &post_lsb[slot * SLOT_SIZE], SLOT_SIZE);
            changes++;
        }
    }
    printf("[*] %d LSB slots changed\n", changes);

    close(dmem_fd); close(pup_fd);
    return (changes > 0) ? 0 : -1;
}

/* ================================================================
 * APPROACH 4: Kernel Memory Scan
 * IMPROVED: uses SDK KERNEL_ADDRESS_TEXT_BASE
 * ================================================================ */
static int approach4_kernel_memscan(void) {
    printf("\n=== APPROACH 4: Kernel Memory Scan ===\n");

    const char *needles[] = {
        "encsrv", "encrypt_service", "pup_key", "decrypt_header",
        "ccp_key", "dec_pup", "Titania", "sceSblSsDecryptPupHeader",
        "sceSblServiceCrypt", NULL
    };

    uint64_t kbase = get_kernel_base();
    size_t scan_size = 32 * 1024 * 1024;
    uint8_t *kbuf = (uint8_t *)malloc(scan_size);
    if (!kbuf) return -1;

    printf("[*] Scanning from 0x%llx...\n", (unsigned long long)kbase);
    if (kernel_copyout(kbase, kbuf, scan_size) != 0) {
        free(kbuf);
        return -1;
    }

    int total_found = 0;
    for (int n = 0; needles[n] != NULL; n++) {
        size_t nlen = strlen(needles[n]);
        for (size_t i = 0; i < scan_size - nlen; i++) {
            if (memcmp(&kbuf[i], needles[n], nlen) != 0) continue;
            uint64_t match_addr = kbase + i;
            printf("[+] Found \"%s\" at 0x%llx\n",
                   needles[n], (unsigned long long)match_addr);

            size_t ctx_start = (i >= 256) ? (i - 256) : 0;
            size_t ctx_end = (i + 256 < scan_size) ? (i + 256) : scan_size;
            output_add_section(SECTION_MEMSCAN, &kbuf[ctx_start],
                               (uint32_t)(ctx_end - ctx_start));
            total_found++;
            i += nlen;
        }
    }

    free(kbuf);
    return (total_found > 0) ? 0 : -1;
}

/* ================================================================
 * APPROACH 5: Targeted Address Read (unchanged from V3)
 * ================================================================ */
static int approach5_read_address(uint64_t addr, uint32_t size) {
    printf("\n=== APPROACH 5: Targeted Address Read ===\n");
    printf("[*] Reading %u bytes from 0x%llx\n", size, (unsigned long long)addr);

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return -1;

    if (addr < 0x100000000ULL) {
        int dmem_fd = open_dmem();
        if (dmem_fd < 0) { free(buf); return -1; }
        void *mapped = mmap(NULL, size, PROT_READ, MAP_SHARED,
                            dmem_fd, (off_t)addr);
        if (mapped == MAP_FAILED) { close(dmem_fd); free(buf); return -1; }
        memcpy(buf, mapped, size);
        munmap(mapped, size);
        close(dmem_fd);
    } else {
        if (kernel_copyout(addr, buf, size) != 0) { free(buf); return -1; }
    }

    hexdump("address read", buf, size);
    output_add_section(SECTION_ADDR_READ, buf, size);
    free(buf);
    return 0;
}

/* ================================================================
 * APPROACH 6: CCP Command Queue Snoop (NEW — read-only)
 *
 * Record CCP queue tail pointers BEFORE and AFTER triggering the
 * DecryptHeader ioctl. If any queue's tail advances, the commands
 * submitted between old and new tail are the CCP operations used
 * for PUP decryption. Dump them raw for PC-side analysis.
 *
 * The command descriptors reveal:
 *   - Which CCP engine is used (AES, PASSTHROUGH, etc.)
 *   - Which SB slot holds the key (for AES with SB key source)
 *   - The key memory address (for AES with memory key source)
 *   - The exact AES mode and key size
 * ================================================================ */
#define CCP_SNOOP_MAX_DESCS 64

static const char *ccp_engine_name(uint32_t id) {
    switch (id) {
        case 0: return "AES";
        case 1: return "XTS-AES";
        case 2: return "SHA";
        case 3: return "RSA";
        case 4: return "ECC";
        case 5: return "PASSTHROUGH";
        case 6: return "ZLIB";
        default: return "UNKNOWN";
    }
}

static const char *ccp_mem_name(uint32_t id) {
    switch (id) {
        case 0: return "system";
        case 1: return "SB";
        case 2: return "local";
        default: return "?";
    }
}

static int approach6_ccp_queue_snoop(void) {
    printf("\n=== APPROACH 6: CCP Command Queue Snoop ===\n");

    int dmem_fd = open_dmem();
    if (dmem_fd < 0) return -1;

    int pup_fd = open(PUP_DEVICE_PATH, O_RDWR);
    if (pup_fd < 0) {
        printf("[!] Cannot open %s — skipping queue snoop\n", PUP_DEVICE_PATH);
        close(dmem_fd);
        return -1;
    }

    int found_cmds = 0;

    for (int b = 0; b < (int)NUM_BAR_CANDIDATES; b++) {
        uint64_t bar = g_bar_candidates[b];

        /* Step 1: snapshot tail pointers for all queues */
        uint32_t pre_tail[CCP_NUM_QUEUES];
        uint32_t pre_head[CCP_NUM_QUEUES];
        int accessible[CCP_NUM_QUEUES];

        for (int q = 0; q < CCP_NUM_QUEUES; q++) {
            accessible[q] = 0;
            uint64_t qaddr = bar + CCP_QUEUE_MMIO_BASE + (q * CCP_QUEUE_STRIDE);
            void *qmap = mmap(NULL, 0x100, PROT_READ, MAP_SHARED,
                              dmem_fd, (off_t)qaddr);
            if (qmap == MAP_FAILED) continue;

            pre_tail[q] = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_TAIL_LO);
            pre_head[q] = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_HEAD_LO);
            munmap(qmap, 0x100);
            accessible[q] = 1;
        }

        /* Step 2: trigger DecryptHeader ioctl */
        struct { void *buffer; size_t length; int type; } dh_args;
        uint8_t dummy_header[0x600];
        memset(dummy_header, 0, sizeof(dummy_header));
        dummy_header[0] = 0x54; dummy_header[1] = 0x14;
        dummy_header[2] = 0xF5; dummy_header[3] = 0xEE;
        dh_args.buffer = dummy_header;
        dh_args.length = sizeof(dummy_header);
        dh_args.type   = 1;

        printf("[*] Triggering DecryptHeader at BAR 0x%llx...\n",
               (unsigned long long)bar);
        ioctl(pup_fd, PUP_IOCTL_DECRYPT_HEADER, &dh_args);

        /* Step 3: read tail pointers again and diff */
        for (int q = 0; q < CCP_NUM_QUEUES; q++) {
            if (!accessible[q]) continue;

            uint64_t qaddr = bar + CCP_QUEUE_MMIO_BASE + (q * CCP_QUEUE_STRIDE);
            void *qmap = mmap(NULL, 0x100, PROT_READ, MAP_SHARED,
                              dmem_fd, (off_t)qaddr);
            if (qmap == MAP_FAILED) continue;

            uint32_t post_tail = *(volatile uint32_t *)
                                 ((uint8_t *)qmap + CCP_REG_TAIL_LO);
            uint32_t post_head = *(volatile uint32_t *)
                                 ((uint8_t *)qmap + CCP_REG_HEAD_LO);
            munmap(qmap, 0x100);

            if (post_tail == pre_tail[q]) continue;

            uint32_t new_bytes;
            if (post_tail > pre_tail[q])
                new_bytes = post_tail - pre_tail[q];
            else
                new_bytes = post_tail + 8192 - pre_tail[q];

            uint32_t ndesc = new_bytes / CCP_DESC_SIZE;
            if (ndesc > CCP_SNOOP_MAX_DESCS) ndesc = CCP_SNOOP_MAX_DESCS;

            printf("[+] Queue %d: tail 0x%08x -> 0x%08x (%u new commands)\n",
                   q, pre_tail[q], post_tail, ndesc);

            /* Step 4: map the descriptor ring and read the commands */
            uint64_t desc_phys = (uint64_t)pre_tail[q];
            uint32_t map_off = (uint32_t)(desc_phys & 0xFFF);
            void *ring_map = mmap(NULL, map_off + ndesc * CCP_DESC_SIZE + 0x1000,
                                  PROT_READ, MAP_SHARED,
                                  dmem_fd, (off_t)(desc_phys & ~0xFFFULL));
            if (ring_map == MAP_FAILED) {
                printf("[!] Cannot map descriptor ring at 0x%08x\n",
                       (uint32_t)desc_phys);
                continue;
            }

            uint8_t *desc_base = (uint8_t *)ring_map + map_off;

            for (uint32_t d = 0; d < ndesc; d++) {
                ccp5_desc_t *cmd = (ccp5_desc_t *)(desc_base + d * CCP_DESC_SIZE);
                uint32_t eng = CCP_DESC_ENGINE(cmd);
                uint32_t func = CCP_DESC_FUNCTION(cmd);
                uint32_t len = CCP_DESC_LENGTH(cmd);
                uint32_t key_mem = CCP_DESC_KEY_MEM(cmd);
                uint32_t key_lo = CCP_DESC_KEY_LO(cmd);

                printf("  [%u] %s func=0x%04x len=%u\n",
                       d, ccp_engine_name(eng), func, len);
                printf("       src=%s@0x%08x  dst=%s@0x%08x\n",
                       ccp_mem_name(CCP_DESC_SRC_MEM(cmd)), CCP_DESC_SRC_LO(cmd),
                       ccp_mem_name(CCP_DESC_DST_MEM(cmd)), CCP_DESC_DST_LO(cmd));

                if (eng == CCP_ENGINE_AES) {
                    int is_decrypt = (func & CCP_AES_DECRYPT) ? 1 : 0;
                    int mode = func & CCP_AES_MODE_MASK;
                    int ksize = (func & CCP_AES_SIZE_MASK) >> 4;
                    int key_sb = (func & CCP_AES_KEY_SB) ? 1 : 0;
                    const char *modes[] = {"ECB","CBC","OFB","CFB","CTR","CMAC"};
                    const char *sizes[] = {"128","192","256"};

                    printf("       >>> AES-%s-%s %s",
                           ksize < 3 ? sizes[ksize] : "?",
                           mode < 6 ? modes[mode] : "?",
                           is_decrypt ? "DECRYPT" : "ENCRYPT");

                    if (key_sb) {
                        printf(", KEY FROM SB SLOT %u", key_lo);
                    } else {
                        printf(", KEY FROM %s@0x%08x",
                               ccp_mem_name(key_mem), key_lo);
                    }
                    printf("\n");
                }
            }

            /* Save raw descriptors to dump */
            uint32_t sec_size = 8 + ndesc * CCP_DESC_SIZE;
            uint8_t *sec_buf = (uint8_t *)malloc(sec_size);
            if (sec_buf) {
                uint32_t queue_id = q;
                uint32_t count = ndesc;
                memcpy(sec_buf, &queue_id, 4);
                memcpy(sec_buf + 4, &count, 4);
                memcpy(sec_buf + 8, desc_base, ndesc * CCP_DESC_SIZE);
                output_add_section(SECTION_CCP_CMD, sec_buf, sec_size);
                free(sec_buf);
            }

            munmap(ring_map, map_off + ndesc * CCP_DESC_SIZE + 0x1000);
            found_cmds = 1;
        }

        if (found_cmds) break;
    }

    close(pup_fd);
    close(dmem_fd);
    return found_cmds ? 0 : -1;
}

/* ================================================================
 * APPROACH 7: Kernel Symbol Resolve (NEW — read-only)
 *
 * Use the SDK's kernel_dynlib_dlsym / kernel_dynlib_resolve to find
 * Sony crypto functions by symbol name. Dump 4KB of code at each
 * resolved address. More reliable than string scanning when the
 * kernel exports these symbols.
 * ================================================================ */
typedef struct {
    uint64_t addr;
    uint32_t code_dumped;
    char     name[60];
} __attribute__((packed)) sym_entry_t;

static int approach7_symbol_resolve(void) {
    printf("\n=== APPROACH 7: Kernel Symbol Resolve ===\n");

    pid_t pid = getpid();

    static const char *sym_names[] = {
        "sceSblServiceCrypt",
        "sceSblSsDecryptPupHeader",
        "sceSblSsDecryptPupSegment",
        "sceSblServiceMailbox",
        "sceSblDriverMapPages",
        "sceSblKeymgrSmCallfunc",
        "sceSblPupUpdateSetKey",
        "sceSblAuthMgrSmStart",
        NULL
    };

    /* Common module handle IDs:
       0 = kernel base, 1 = libkernel, 0x2001 = libSceSbl */
    static const uint32_t handles[] = { 0, 1, 0x2001, 0x2002, 0x13 };
    int num_handles = sizeof(handles) / sizeof(handles[0]);

    sym_entry_t entries[16];
    int entry_count = 0;
    int total_resolved = 0;

    for (int s = 0; sym_names[s] && entry_count < 16; s++) {
        intptr_t addr = 0;

        for (int h = 0; h < num_handles && addr == 0; h++) {
            addr = kernel_dynlib_dlsym(pid, handles[h], sym_names[s]);
            if (addr != 0) {
                printf("[+] %s = 0x%llx (handle=%u)\n",
                       sym_names[s], (unsigned long long)addr, handles[h]);
            }
        }

        if (addr == 0) {
            addr = kernel_dynlib_resolve(pid, 0, sym_names[s]);
            if (addr != 0) {
                printf("[+] %s = 0x%llx (via NID resolve)\n",
                       sym_names[s], (unsigned long long)addr);
            }
        }

        if (addr != 0) {
            sym_entry_t *e = &entries[entry_count];
            e->addr = (uint64_t)addr;
            strncpy(e->name, sym_names[s], sizeof(e->name) - 1);
            e->name[sizeof(e->name) - 1] = '\0';

            uint8_t code[4096];
            if (kernel_copyout(addr, code, sizeof(code)) == 0) {
                e->code_dumped = sizeof(code);
                hexdump(sym_names[s], code, 128);
                output_add_section(SECTION_SYMRESOLVE, code, sizeof(code));
            } else {
                e->code_dumped = 0;
                printf("[!] Failed to dump code at 0x%llx\n",
                       (unsigned long long)addr);
            }

            entry_count++;
            total_resolved++;
        } else {
            printf("[-] %s — not found\n", sym_names[s]);
        }
    }

    if (entry_count > 0) {
        output_add_section(SECTION_SYMRESOLVE,
                          entries, entry_count * sizeof(sym_entry_t));
    }

    printf("[*] Resolved %d / %d symbols\n", total_resolved,
           (int)(sizeof(sym_names)/sizeof(sym_names[0])) - 1);
    return total_resolved > 0 ? 0 : -1;
}

/* ================================================================
 * APPROACH 8: CCP PASSTHROUGH Key Extract (NEW — writes to CCP)
 *
 * Submit a CCP PASSTHROUGH command that copies data from an SB
 * (Secure Buffer / LSB) slot into system memory we control.
 *
 * The private mask only blocks direct CPU MMIO reads of SB slots.
 * A CCP-internal PASSTHROUGH operation copies between any source
 * and destination the CCP itself can access — including private
 * slots the CPU can't read via MMIO.
 *
 * Requires: -p <slot_number> [-q <queue_number>]
 * WARNING: Writes to CCP command queue. Non-destructive but
 *          aggressive. May hang CCP if parameters are wrong.
 * ================================================================ */
static int approach8_passthrough(int sb_slot, int queue_id) {
    printf("\n=== APPROACH 8: CCP PASSTHROUGH Extract ===\n");
    printf("[*] Target: SB slot %d via queue %d\n", sb_slot, queue_id);

    int dmem_fd = open_dmem();
    if (dmem_fd < 0) return -1;

    int found = 0;

    for (int b = 0; b < (int)NUM_BAR_CANDIDATES; b++) {
        uint64_t bar = g_bar_candidates[b];
        uint64_t qaddr = bar + CCP_QUEUE_MMIO_BASE + (queue_id * CCP_QUEUE_STRIDE);

        /* Map queue registers with read+write */
        void *qmap = mmap(NULL, 0x100, PROT_READ | PROT_WRITE, MAP_SHARED,
                          dmem_fd, (off_t)qaddr);
        if (qmap == MAP_FAILED) continue;

        uint32_t ctrl = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_CONTROL);
        uint32_t status = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_STATUS);
        uint32_t tail = *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_TAIL_LO);

        printf("[+] BAR 0x%llx queue %d: ctrl=0x%x status=0x%x tail=0x%08x\n",
               (unsigned long long)bar, queue_id, ctrl, status, tail);

        if (tail == 0) {
            munmap(qmap, 0x100);
            continue;
        }

        /* Allocate output buffer: use a physical page via dmem0.
         * Pick an address 4KB past the current tail — this is in the
         * queue's DMA region and should be valid system RAM. */
        uint64_t out_phys = ((uint64_t)tail & ~0xFFFULL) + 0x2000;
        void *out_map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
                             dmem_fd, (off_t)out_phys);
        if (out_map == MAP_FAILED) {
            printf("[!] Cannot map output page at 0x%llx, trying 0x80000\n",
                   (unsigned long long)out_phys);
            out_phys = 0x80000ULL;
            out_map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
                           dmem_fd, (off_t)out_phys);
            if (out_map == MAP_FAILED) {
                printf("[!] Cannot map any output page\n");
                munmap(qmap, 0x100);
                continue;
            }
        }

        memset(out_map, 0xCC, SLOT_SIZE);
        printf("[+] Output buffer at phys 0x%llx\n", (unsigned long long)out_phys);

        /* Build PASSTHROUGH descriptor: SB slot → system memory */
        ccp5_desc_t pt_desc;
        memset(&pt_desc, 0, sizeof(pt_desc));

        pt_desc.dw[0] = (CCP_ENGINE_PASSTHROUGH << 20)
                       | (1 << 4)    /* EOM */
                       | (1 << 3)    /* INIT */
                       | (1 << 1)    /* SOC */
                       | (1 << 0);   /* IOC */
        pt_desc.dw[1] = SLOT_SIZE;
        pt_desc.dw[2] = (uint32_t)sb_slot;
        pt_desc.dw[3] = (CCP_MEMTYPE_SB << 16);
        pt_desc.dw[4] = (uint32_t)(out_phys & 0xFFFFFFFF);
        pt_desc.dw[5] = (uint32_t)((out_phys >> 32) & 0xFFFF)
                       | (CCP_MEMTYPE_SYSTEM << 16);
        pt_desc.dw[6] = 0;
        pt_desc.dw[7] = 0;

        printf("[*] Descriptor built:\n");
        for (int i = 0; i < 8; i++)
            printf("    dw[%d] = 0x%08x\n", i, pt_desc.dw[i]);

        /* Write descriptor to queue ring buffer at current tail */
        uint64_t tail_phys = (uint64_t)tail;
        uint32_t tail_off = (uint32_t)(tail_phys & 0xFFF);
        void *tail_map = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
                              dmem_fd, (off_t)(tail_phys & ~0xFFFULL));
        if (tail_map == MAP_FAILED) {
            printf("[!] Cannot map queue ring at tail 0x%08x\n", tail);
            munmap(out_map, 0x1000);
            munmap(qmap, 0x100);
            continue;
        }

        memcpy((uint8_t *)tail_map + tail_off, &pt_desc, CCP_DESC_SIZE);
        printf("[+] Descriptor written to queue ring at 0x%08x\n", tail);

        munmap(tail_map, 0x1000);

        /* Advance tail pointer to submit the command */
        uint32_t new_tail = tail + CCP_DESC_SIZE;
        printf("[*] Advancing tail: 0x%08x -> 0x%08x\n", tail, new_tail);
        *(volatile uint32_t *)((uint8_t *)qmap + CCP_REG_TAIL_LO) = new_tail;

        /* Poll for completion: wait for head to catch up */
        printf("[*] Waiting for CCP to process...\n");
        for (int poll = 0; poll < 10000; poll++) {
            uint32_t head = *(volatile uint32_t *)
                            ((uint8_t *)qmap + CCP_REG_HEAD_LO);
            if (head >= new_tail) break;
            usleep(10);
        }

        uint32_t final_head = *(volatile uint32_t *)
                              ((uint8_t *)qmap + CCP_REG_HEAD_LO);
        uint32_t final_status = *(volatile uint32_t *)
                                ((uint8_t *)qmap + CCP_REG_STATUS);
        printf("[*] head=0x%08x status=0x%08x\n", final_head, final_status);

        munmap(qmap, 0x100);

        /* Read the result */
        uint8_t result[SLOT_SIZE];
        memcpy(result, out_map, SLOT_SIZE);
        munmap(out_map, 0x1000);

        /* Check if the output changed from our 0xCC fill */
        int changed = 0;
        for (int i = 0; i < SLOT_SIZE; i++) {
            if (result[i] != 0xCC) { changed = 1; break; }
        }

        if (changed) {
            printf("[+] PASSTHROUGH succeeded! SB slot %d data:\n", sb_slot);
            hexdump("SB slot data", result, SLOT_SIZE);
            output_add_section(SECTION_PASSTHROUGH, result, SLOT_SIZE);
            found = 1;
        } else {
            printf("[!] Output unchanged — PASSTHROUGH may have failed or "
                   "slot is empty\n");
            printf("[*] Try a different BAR, queue, or verify slot number "
                   "from Approach 6 output\n");
        }

        if (found) break;
    }

    close(dmem_fd);
    return found ? 0 : -1;
}

/* ================================================================
 * APPROACH 9: Decrypt Oracle (NEW — uses real PUP data)
 *
 * Feed a real encrypted PUP header from /data/pup_header.bin to
 * the DecryptHeader ioctl and capture the result. If the ioctl
 * decrypts in-place, we get the plaintext back.
 *
 * Upload the encrypted PUP header via FTP before running:
 *   python -c "
 *     with open('PS5UPDATE14.00.PUP','rb') as f:
 *         f.seek(0x200)  # skip BLS outer, adjust offset as needed
 *         data = f.read(0x1000)
 *     with open('pup_header.bin','wb') as f:
 *         f.write(data)
 *   "
 *   ftp> put pup_header.bin /data/pup_header.bin
 *
 * Then run: ./ps5_key_extract -d
 * ================================================================ */
#define ORACLE_HEADER_PATH  "/data/pup_header.bin"
#define ORACLE_MAX_SIZE     0x10000  /* 64KB max */

static int approach9_decrypt_oracle(void) {
    printf("\n=== APPROACH 9: Decrypt Oracle ===\n");

    int hdr_fd = open(ORACLE_HEADER_PATH, O_RDONLY);
    if (hdr_fd < 0) {
        printf("[!] Cannot open %s\n", ORACLE_HEADER_PATH);
        printf("[*] Upload the encrypted PUP header via FTP first.\n");
        printf("[*] On PC, extract it from the BLS container:\n");
        printf("    python pup.py extract-header PS5UPDATE14.00.PUP "
               "pup_header.bin\n");
        printf("    ftp> put pup_header.bin /data/pup_header.bin\n");
        return -1;
    }

    /* Read the encrypted header */
    uint8_t *enc_buf = (uint8_t *)malloc(ORACLE_MAX_SIZE);
    uint8_t *dec_buf = (uint8_t *)malloc(ORACLE_MAX_SIZE);
    if (!enc_buf || !dec_buf) {
        printf("[!] malloc failed\n");
        if (enc_buf) free(enc_buf);
        if (dec_buf) free(dec_buf);
        close(hdr_fd);
        return -1;
    }

    ssize_t hdr_size = read(hdr_fd, enc_buf, ORACLE_MAX_SIZE);
    close(hdr_fd);

    if (hdr_size <= 0) {
        printf("[!] Failed to read header file (size=%zd)\n", hdr_size);
        free(enc_buf); free(dec_buf);
        return -1;
    }

    printf("[+] Read %zd bytes from %s\n", hdr_size, ORACLE_HEADER_PATH);
    hexdump("encrypted header (first bytes)", enc_buf, hdr_size > 64 ? 64 : hdr_size);

    output_add_section(SECTION_ORACLE_IN, enc_buf, (uint32_t)hdr_size);

    /* Copy to decrypt buffer (ioctl may modify in-place) */
    memcpy(dec_buf, enc_buf, hdr_size);

    int pup_fd = open(PUP_DEVICE_PATH, O_RDWR);
    if (pup_fd < 0) {
        printf("[!] Cannot open %s\n", PUP_DEVICE_PATH);
        free(enc_buf); free(dec_buf);
        return -1;
    }

    /* Try all three type values */
    int types[] = { 1, 0, 2 };
    const char *type_names[] = { "system update", "recovery", "type 2" };

    for (int t = 0; t < 3; t++) {
        memcpy(dec_buf, enc_buf, hdr_size);

        struct { void *buffer; size_t length; int type; } dh_args;
        dh_args.buffer = dec_buf;
        dh_args.length = (size_t)hdr_size;
        dh_args.type   = types[t];

        printf("[*] DecryptHeader type=%d (%s)...\n", types[t], type_names[t]);
        int ret = ioctl(pup_fd, PUP_IOCTL_DECRYPT_HEADER, &dh_args);
        printf("[*] ioctl returned %d\n", ret);

        /* Check if buffer changed */
        int changed = 0;
        for (ssize_t i = 0; i < hdr_size; i++) {
            if (dec_buf[i] != enc_buf[i]) { changed = 1; break; }
        }

        if (changed) {
            printf("[+] Buffer CHANGED after decrypt (type=%d)!\n", types[t]);
            hexdump("decrypted header (first bytes)", dec_buf,
                    hdr_size > 128 ? 128 : hdr_size);
            output_add_section(SECTION_ORACLE_OUT, dec_buf, (uint32_t)hdr_size);

            /* Check for PUP magic in decrypted output */
            if (hdr_size >= 4) {
                uint32_t magic;
                memcpy(&magic, dec_buf, 4);
                if (magic == 0xEEF51454) {
                    printf("[!!!] Decrypted PUP magic found! Oracle SUCCESS!\n");
                    printf("[!!!] The PS5 decrypted the header correctly.\n");
                }
            }
        } else {
            printf("[*] Buffer unchanged for type=%d\n", types[t]);
        }
    }

    close(pup_fd);
    free(enc_buf);
    free(dec_buf);
    return 0;
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    printf("=== PS5 PUP Key Extractor v4 ===\n");
    printf("FW version: 0x%08x\n", kernel_get_fw_version());
    printf("Kernel text base: 0x%llx\n",
           (unsigned long long)KERNEL_ADDRESS_TEXT_BASE);
    printf("Output: /data/pup_key_dump.bin\n\n");

    /* Parse arguments */
    uint64_t target_addr = 0;
    uint32_t target_size = 4096;
    int addr_mode = 0;
    int passthrough_mode = 0;
    int passthrough_slot = -1;
    int passthrough_queue = 0;
    int oracle_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            target_addr = strtoull(argv[++i], NULL, 0);
            addr_mode = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            target_size = (uint32_t)strtoul(argv[++i], NULL, 0);
            if (target_size > 65536) target_size = 65536;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            passthrough_slot = (int)strtol(argv[++i], NULL, 0);
            passthrough_mode = 1;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            passthrough_queue = (int)strtol(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-d") == 0) {
            oracle_mode = 1;
        }
    }

    output_begin();

    if (addr_mode) {
        approach5_read_address(target_addr, target_size);
    } else if (passthrough_mode) {
        if (passthrough_slot < 0 || passthrough_slot > 127) {
            printf("[!] Invalid slot number %d (must be 0-127)\n",
                   passthrough_slot);
            return 1;
        }
        approach8_passthrough(passthrough_slot, passthrough_queue);
    } else if (oracle_mode) {
        approach9_decrypt_oracle();
    } else {
        /* Full scan — run approaches 1-7 (all read-only) */
        int r1 = approach1_ccp_lsb_dump();
        int r2 = approach2_ioctl_handler_scan();
        int r3 = approach3_instrumented_decrypt();
        int r4 = approach4_kernel_memscan();
        int r6 = approach6_ccp_queue_snoop();
        int r7 = approach7_symbol_resolve();

        printf("\n=== Summary ===\n");
        printf("Approach 1 (CCP LSB + queue regs):  %s\n",
               r1 == 0 ? "OK" : "FAILED");
        printf("Approach 2 (full handler dump):      %s\n",
               r2 == 0 ? "OK" : "FAILED");
        printf("Approach 3 (instrumented decrypt):   %s\n",
               r3 == 0 ? "OK" : "FAILED");
        printf("Approach 4 (kernel mem scan):        %s\n",
               r4 == 0 ? "OK" : "FAILED");
        printf("Approach 6 (CCP queue snoop):        %s\n",
               r6 == 0 ? "OK" : "FAILED");
        printf("Approach 7 (symbol resolve):         %s\n",
               r7 == 0 ? "OK" : "FAILED");

        printf("\n--- Next steps ---\n");
        printf("1. Transfer dump to PC:  python analyze_dump.py pup_key_dump.bin\n");
        printf("2. If CCP snoop found AES with SB key:\n");
        printf("   ./ps5_key_extract -p <slot> [-q <queue>]\n");
        printf("3. If handler/symbol analysis found key address:\n");
        printf("   ./ps5_key_extract -a <address> -s 256\n");
        printf("4. Decrypt oracle (upload PUP header first):\n");
        printf("   ./ps5_key_extract -d\n");
    }

    output_write("/data/pup_key_dump.bin");
    return 0;
}
