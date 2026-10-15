/*
 * ps5_key_extract.c — PUP header decryption key extractor for jailbroken PS5
 *
 * Target: PS5 FW 13.60 or below with kernel R/W (e.g. Byepervisor Reborn + Relapse)
 * Build: compile for FreeBSD 11 amd64, load via payload loader
 * Output: /data/pup_key_dump.bin (structured binary with section headers)
 *
 * Strategy: Chain approach 2 → approach 1.
 *   1) Dump the ioctl handler code (approach 2) — needs only kernel R/W
 *   2) RE the handler on PC to find which CCP slot / kernel address holds the key
 *   3) Use approach 5 (read-address mode) to read that specific location
 *   4) Approach 1 (CCP LSB dump) may catch it directly if slots are readable
 *
 * All operations are READ-ONLY. Nothing is written to kernel or hardware state.
 *
 * Usage:
 *   ./ps5_key_extract                    — run all approaches
 *   ./ps5_key_extract -a 0xFFFF...       — read 4KB from a specific kernel address
 *   ./ps5_key_extract -a 0xFFFF... -s N  — read N bytes from that address
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

/* ---------- kernel R/W primitives (framework-dependent) ---------- */
extern uint64_t kernel_read64(uint64_t kaddr);
extern uint32_t kernel_read32(uint64_t kaddr);
extern int      kernel_copyout(uint64_t kaddr, void *uaddr, size_t len);

/* ---------- output format (v2) ---------- */
#define DUMP_MAGIC          0x505550444D50ULL  /* "PUPDMP\0\0" */
#define DUMP_VERSION        2

#define SECTION_LSB         0x01
#define SECTION_IOCTL       0x02
#define SECTION_SNAP_PRE    0x03
#define SECTION_SNAP_POST   0x04
#define SECTION_MEMSCAN     0x05
#define SECTION_CDEVSW      0x06
#define SECTION_CCP_REGS    0x07
#define SECTION_ADDR_READ   0x08
#define SECTION_HANDLER_OPEN  0x09
#define SECTION_HANDLER_CLOSE 0x0A

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

/* Queue register offsets */
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

/* LSB region candidates from CCP BAR */
#define LSB_OFFSET_A         0x8000
#define LSB_OFFSET_B         0x10000
#define LSB_OFFSET_C         0x4000

/* LSB geometry: 8 LSBs x 16 slots x 32 bytes = 4096 bytes */
#define LSB_COUNT            8
#define SLOTS_PER_LSB        16
#define SLOT_SIZE            32
#define LSB_TOTAL_SIZE       (LSB_COUNT * SLOTS_PER_LSB * SLOT_SIZE)

/* ---------- PUP ioctl constants (from ps5-pup-decrypt encryptsrv.c) ---------- */
#define PUP_DEVICE_PATH      "/dev/pup_update0"

/* Complete ioctl map for /dev/pup_update0:
 *   0xC0104401  VerifyBlsHeader       { void* buf, u64 len, u64 unk }
 *   0xC0184402  DecryptHeader         { void* buf, u64 len, int type }
 *   0xC0184403  VerifyPupAdditionalSign { u16 idx, void* buf, u64 len }
 *   0xC0184404  VerifyPupWatermark    { u16 idx, void* buf, u64 len }
 *   0xC0184405  DecryptSegment        { u16 idx, void* buf, u64 len }
 *   0xC0284406  DecryptSegmentBlock   { u16 entry_idx, u16 block_idx,
 *                                       void* block_buf, u64 block_len,
 *                                       void* table_buf, u64 table_len }
 *
 * DecryptHeader 'type' arg selects the key:
 *   translate_type(): 0,3->0  1,4->1  2,5->2
 *   PS5UPDATE1.PUP (system update) = type 1
 *   PS5UPDATE2.PUP (recovery)      = type 0
 *
 * The d_ioctl handler dispatches on type to load different keys.
 * Our automated disassembly (analyze_dump.py) traces this dispatch.
 */
#define PUP_IOCTL_VERIFY_BLS      0xC0104401
#define PUP_IOCTL_DECRYPT_HEADER  0xC0184402
#define PUP_IOCTL_VERIFY_ADDSIGN  0xC0184403
#define PUP_IOCTL_VERIFY_WATER    0xC0184404
#define PUP_IOCTL_DECRYPT_SEG     0xC0184405
#define PUP_IOCTL_DECRYPT_BLOCK   0xC0284406

/* ---------- PS5 kernel constants (FreeBSD 11 based) ---------- */
#define KERNEL_BASE_PRIMARY   0xFFFFFFFF82200000ULL
#define KERNEL_BASE_FALLBACK  0xFFFFFFFF80000000ULL

/* FreeBSD 11 cdevsw field offsets */
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

/* Handler dump size — 16KB gives enough room for full function + callees */
#define HANDLER_DUMP_SIZE    (16 * 1024)

/* ---------- globals ---------- */
#define OUTPUT_MAX           (512 * 1024)
static uint8_t  g_output[OUTPUT_MAX];
static uint32_t g_output_pos = 0;
static uint32_t g_section_count = 0;

#define MAX_SECTIONS 64
static section_header_t g_sections[MAX_SECTIONS];

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

/* ================================================================
 * APPROACH 1: CCP LSB Key Slot Dump + Queue Register Dump
 *
 * Map the AMD CCP v5 MMIO region and read all 128 LSB key slots.
 * Also dump all queue configuration registers (control, status,
 * public/private masks) — these tell us which slots are CPU-readable.
 * ================================================================ */
static int approach1_ccp_lsb_dump(void) {
    printf("\n=== APPROACH 1: CCP LSB Key Slot Dump + Queue Registers ===\n");

    int dmem_fd = open("/dev/dmem0", O_RDWR);
    if (dmem_fd < 0) {
        dmem_fd = open("/dev/mem", O_RDWR);
        if (dmem_fd < 0) {
            printf("[!] Cannot open /dev/dmem0 or /dev/mem\n");
            return -1;
        }
        printf("[+] Opened /dev/mem\n");
    } else {
        printf("[+] Opened /dev/dmem0\n");
    }

    uint64_t bar_candidates[] = {
        0xE0100000ULL,
        0xFED80000ULL,
        0xFEC10000ULL,
        0x03000000ULL,
    };

    uint32_t lsb_offsets[] = { LSB_OFFSET_A, LSB_OFFSET_B, LSB_OFFSET_C };
    uint8_t  lsb_data[LSB_TOTAL_SIZE];
    int      found_any = 0;

    for (int b = 0; b < (int)(sizeof(bar_candidates)/sizeof(bar_candidates[0])); b++) {
        uint64_t bar = bar_candidates[b];

        for (int lo = 0; lo < (int)(sizeof(lsb_offsets)/sizeof(lsb_offsets[0])); lo++) {
            uint64_t lsb_phys = bar + lsb_offsets[lo];
            printf("[*] Trying BAR 0x%llx + LSB offset 0x%x = 0x%llx\n",
                   (unsigned long long)bar, lsb_offsets[lo],
                   (unsigned long long)lsb_phys);

            void *mapped = mmap(NULL, LSB_TOTAL_SIZE,
                                PROT_READ, MAP_SHARED,
                                dmem_fd, (off_t)lsb_phys);
            if (mapped == MAP_FAILED) {
                printf("[!] mmap failed for 0x%llx\n", (unsigned long long)lsb_phys);
                continue;
            }

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

        /* Dump ALL queue registers — not just masks */
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

        if (got_regs) {
            output_add_section(SECTION_CCP_REGS, queue_regs, sizeof(queue_regs));
        }
    }

    close(dmem_fd);
    if (!found_any) {
        printf("[!] No non-zero LSB data found via MMIO\n");
    }
    return found_any ? 0 : -1;
}

/* ================================================================
 * APPROACH 2: EncryptService Full Handler Dump
 *
 * Find the pup_update device's cdevsw in kernel memory, then dump:
 *   - The full cdevsw struct (all function pointers)
 *   - 16KB of d_ioctl handler code
 *   - 16KB of d_open handler code (key loading may happen here)
 *   - 16KB of d_close handler code
 *
 * Disassemble all three on PC — the key's journey from storage
 * into the CCP slot is visible somewhere in these functions.
 * ================================================================ */
static int approach2_ioctl_handler_scan(void) {
    printf("\n=== APPROACH 2: EncryptService Full Handler Dump ===\n");

    uint64_t kernel_bases[] = { KERNEL_BASE_PRIMARY, KERNEL_BASE_FALLBACK };
    const char *search_str = "pup_update";
    size_t search_len = strlen(search_str);

    size_t scan_size = 32 * 1024 * 1024;
    uint8_t *kbuf = (uint8_t *)malloc(scan_size);
    if (!kbuf) {
        printf("[!] malloc failed for kernel scan buffer\n");
        return -1;
    }

    for (int kb = 0; kb < (int)(sizeof(kernel_bases)/sizeof(kernel_bases[0])); kb++) {
        uint64_t kbase = kernel_bases[kb];
        printf("[*] Scanning kernel at base 0x%llx...\n", (unsigned long long)kbase);

        if (kernel_copyout(kbase, kbuf, scan_size) != 0) {
            printf("[!] kernel_copyout failed for base 0x%llx\n", (unsigned long long)kbase);
            continue;
        }

        for (size_t i = 0; i < scan_size - search_len; i++) {
            if (memcmp(&kbuf[i], search_str, search_len) == 0 && kbuf[i + search_len] == '\0') {
                uint64_t str_kaddr = kbase + i;
                printf("[+] Found \"%s\" at kernel address 0x%llx\n",
                       search_str, (unsigned long long)str_kaddr);

                for (size_t j = 0; j < scan_size - 8; j += 8) {
                    uint64_t val;
                    memcpy(&val, &kbuf[j], 8);
                    if (val == str_kaddr) {
                        uint64_t ptr_kaddr = kbase + j;
                        uint64_t cdevsw_base = ptr_kaddr - CDEVSW_D_NAME;

                        printf("[+] Pointer to string at 0x%llx\n",
                               (unsigned long long)ptr_kaddr);
                        printf("[+] Candidate cdevsw at 0x%llx\n",
                               (unsigned long long)cdevsw_base);

                        /* Read all function pointers from cdevsw */
                        uint64_t d_open  = kernel_read64(cdevsw_base + CDEVSW_D_OPEN);
                        uint64_t d_close = kernel_read64(cdevsw_base + CDEVSW_D_CLOSE);
                        uint64_t d_read  = kernel_read64(cdevsw_base + CDEVSW_D_READ);
                        uint64_t d_write = kernel_read64(cdevsw_base + CDEVSW_D_WRITE);
                        uint64_t d_ioctl = kernel_read64(cdevsw_base + CDEVSW_D_IOCTL);
                        uint64_t d_poll  = kernel_read64(cdevsw_base + CDEVSW_D_POLL);
                        uint64_t d_mmap  = kernel_read64(cdevsw_base + CDEVSW_D_MMAP);

                        printf("[+] cdevsw function pointers:\n");
                        printf("    d_open   = 0x%llx\n", (unsigned long long)d_open);
                        printf("    d_close  = 0x%llx\n", (unsigned long long)d_close);
                        printf("    d_read   = 0x%llx\n", (unsigned long long)d_read);
                        printf("    d_write  = 0x%llx\n", (unsigned long long)d_write);
                        printf("    d_ioctl  = 0x%llx\n", (unsigned long long)d_ioctl);
                        printf("    d_poll   = 0x%llx\n", (unsigned long long)d_poll);
                        printf("    d_mmap   = 0x%llx\n", (unsigned long long)d_mmap);

                        if (d_ioctl < 0xFFFFFFFF80000000ULL) {
                            printf("[!] d_ioctl address looks invalid, skipping\n");
                            continue;
                        }

                        /* Dump the raw cdevsw struct */
                        uint8_t cdevsw_raw[CDEVSW_SIZE];
                        if (kernel_copyout(cdevsw_base, cdevsw_raw, sizeof(cdevsw_raw)) == 0) {
                            printf("[+] Dumped cdevsw struct (%d bytes)\n", CDEVSW_SIZE);
                            output_add_section(SECTION_CDEVSW, cdevsw_raw, sizeof(cdevsw_raw));
                        }

                        /* Dump 16KB of d_ioctl handler */
                        uint8_t handler_code[HANDLER_DUMP_SIZE];
                        if (kernel_copyout(d_ioctl, handler_code, sizeof(handler_code)) == 0) {
                            printf("[+] Dumped d_ioctl handler (%d bytes)\n", HANDLER_DUMP_SIZE);
                            hexdump("d_ioctl first 128 bytes", handler_code, 128);
                            output_add_section(SECTION_IOCTL, handler_code, sizeof(handler_code));
                        } else {
                            printf("[!] Failed to dump d_ioctl handler\n");
                        }

                        /* Dump 16KB of d_open handler — key loading may happen here */
                        if (d_open >= 0xFFFFFFFF80000000ULL) {
                            uint8_t open_code[HANDLER_DUMP_SIZE];
                            if (kernel_copyout(d_open, open_code, sizeof(open_code)) == 0) {
                                printf("[+] Dumped d_open handler (%d bytes)\n", HANDLER_DUMP_SIZE);
                                hexdump("d_open first 128 bytes", open_code, 128);
                                output_add_section(SECTION_HANDLER_OPEN, open_code, sizeof(open_code));
                            } else {
                                printf("[!] Failed to dump d_open handler\n");
                            }
                        }

                        /* Dump 16KB of d_close handler */
                        if (d_close >= 0xFFFFFFFF80000000ULL) {
                            uint8_t close_code[HANDLER_DUMP_SIZE];
                            if (kernel_copyout(d_close, close_code, sizeof(close_code)) == 0) {
                                printf("[+] Dumped d_close handler (%d bytes)\n", HANDLER_DUMP_SIZE);
                                output_add_section(SECTION_HANDLER_CLOSE, close_code, sizeof(close_code));
                            } else {
                                printf("[!] Failed to dump d_close handler\n");
                            }
                        }

                        free(kbuf);
                        return 0;
                    }
                }
            }
        }
    }

    free(kbuf);
    printf("[!] Could not locate pup_update cdevsw\n");
    return -1;
}

/* ================================================================
 * APPROACH 3: Instrumented PUP Decrypt (LSB snapshot)
 *
 * Snapshot all CCP LSB key slots BEFORE and AFTER issuing the
 * DecryptPupHeader ioctl. Any slot that changed was loaded by
 * the security processor for decryption.
 *
 * NOTE: PSP may lock out after boot, making this less reliable
 * on newer firmware. Still worth running for the diff data.
 * ================================================================ */
static int approach3_instrumented_decrypt(void) {
    printf("\n=== APPROACH 3: Instrumented PUP Decrypt ===\n");

    int pup_fd = open(PUP_DEVICE_PATH, O_RDWR);
    if (pup_fd < 0) {
        printf("[!] Cannot open %s — device may not exist or access denied\n",
               PUP_DEVICE_PATH);
        printf("[*] Skipping approach 3 (needs %s)\n", PUP_DEVICE_PATH);
        return -1;
    }

    printf("[+] Opened %s\n", PUP_DEVICE_PATH);

    int dmem_fd = open("/dev/dmem0", O_RDWR);
    if (dmem_fd < 0) {
        printf("[!] Cannot open /dev/dmem0 for LSB snapshot\n");
        close(pup_fd);
        return -1;
    }

    uint64_t lsb_phys = 0x03000000ULL + LSB_OFFSET_A;
    uint8_t pre_lsb[LSB_TOTAL_SIZE];
    uint8_t post_lsb[LSB_TOTAL_SIZE];

    void *mapped = mmap(NULL, LSB_TOTAL_SIZE, PROT_READ, MAP_SHARED,
                        dmem_fd, (off_t)lsb_phys);
    if (mapped == MAP_FAILED) {
        printf("[!] Cannot map LSB region for snapshot\n");
        close(dmem_fd);
        close(pup_fd);
        return -1;
    }

    memcpy(pre_lsb, mapped, LSB_TOTAL_SIZE);
    printf("[+] Pre-decrypt LSB snapshot captured\n");
    output_add_section(SECTION_SNAP_PRE, pre_lsb, LSB_TOTAL_SIZE);

    /* Try to invoke DecryptHeader ioctl to trigger key loading.
     * struct decrypt_header_args { void* buffer; size_t length; int type; }
     * type 1 = PS5UPDATE1.PUP (system update key — our target)
     * Even if the decrypt fails (no valid PUP header in buffer), the
     * security processor may still load the key into CCP slots. */
    {
        struct {
            void   *buffer;
            size_t  length;
            int     type;
        } dh_args;
        uint8_t dummy_header[0x600];
        memset(dummy_header, 0, sizeof(dummy_header));
        /* Set PUP magic so the handler at least starts processing */
        dummy_header[0] = 0x54; dummy_header[1] = 0x14;
        dummy_header[2] = 0xF5; dummy_header[3] = 0xEE;

        dh_args.buffer = dummy_header;
        dh_args.length = sizeof(dummy_header);
        dh_args.type   = 1; /* system update key */

        printf("[*] Invoking DecryptHeader ioctl (type=1) to trigger key load...\n");
        int ret = ioctl(pup_fd, PUP_IOCTL_DECRYPT_HEADER, &dh_args);
        printf("[*] ioctl returned %d (key may have been loaded regardless of result)\n", ret);
    }

    memcpy(post_lsb, mapped, LSB_TOTAL_SIZE);
    munmap(mapped, LSB_TOTAL_SIZE);
    printf("[+] Post-decrypt LSB snapshot captured\n");
    output_add_section(SECTION_SNAP_POST, post_lsb, LSB_TOTAL_SIZE);

    int changes = 0;
    for (int slot = 0; slot < LSB_COUNT * SLOTS_PER_LSB; slot++) {
        uint8_t *pre  = &pre_lsb[slot * SLOT_SIZE];
        uint8_t *post = &post_lsb[slot * SLOT_SIZE];
        if (memcmp(pre, post, SLOT_SIZE) != 0) {
            printf("[+] LSB slot %d CHANGED during decrypt!\n", slot);
            hexdump("  before", pre, SLOT_SIZE);
            hexdump("  after ", post, SLOT_SIZE);
            changes++;
        }
    }

    printf("[*] %d LSB slots changed\n", changes);
    close(dmem_fd);
    close(pup_fd);
    return (changes > 0) ? 0 : -1;
}

/* ================================================================
 * APPROACH 4: Kernel Memory Scan
 *
 * Search kernel memory near known strings for key-like data.
 * Dump 512 bytes of surrounding context for each match.
 * ================================================================ */
static int approach4_kernel_memscan(void) {
    printf("\n=== APPROACH 4: Kernel Memory Scan ===\n");

    const char *needles[] = {
        "encsrv",
        "encrypt_service",
        "pup_key",
        "decrypt_header",
        "ccp_key",
        "dec_pup",
        "Titania",
        "sceSblSsDecryptPupHeader",
        "sceSblServiceCrypt",
        NULL
    };

    uint64_t kernel_bases[] = { KERNEL_BASE_PRIMARY, KERNEL_BASE_FALLBACK };
    size_t scan_size = 32 * 1024 * 1024;
    uint8_t *kbuf = (uint8_t *)malloc(scan_size);
    if (!kbuf) {
        printf("[!] malloc failed\n");
        return -1;
    }

    int total_found = 0;

    for (int kb = 0; kb < (int)(sizeof(kernel_bases)/sizeof(kernel_bases[0])); kb++) {
        uint64_t kbase = kernel_bases[kb];
        printf("[*] Scanning kernel at base 0x%llx...\n", (unsigned long long)kbase);

        if (kernel_copyout(kbase, kbuf, scan_size) != 0) {
            printf("[!] kernel_copyout failed for 0x%llx\n", (unsigned long long)kbase);
            continue;
        }

        for (int n = 0; needles[n] != NULL; n++) {
            size_t nlen = strlen(needles[n]);
            for (size_t i = 0; i < scan_size - nlen; i++) {
                if (memcmp(&kbuf[i], needles[n], nlen) == 0) {
                    uint64_t match_addr = kbase + i;
                    printf("[+] Found \"%s\" at 0x%llx\n",
                           needles[n], (unsigned long long)match_addr);

                    size_t ctx_start = (i >= 256) ? (i - 256) : 0;
                    size_t ctx_end = i + 256;
                    if (ctx_end > scan_size) ctx_end = scan_size;
                    size_t ctx_len = ctx_end - ctx_start;

                    char label[128];
                    snprintf(label, sizeof(label), "context around \"%s\"", needles[n]);
                    hexdump(label, &kbuf[ctx_start], ctx_len);

                    output_add_section(SECTION_MEMSCAN, &kbuf[ctx_start], (uint32_t)ctx_len);
                    total_found++;

                    i += nlen;
                }
            }
        }

        if (total_found > 0) break;
    }

    free(kbuf);
    printf("[*] Total string matches: %d\n", total_found);
    return (total_found > 0) ? 0 : -1;
}

/* ================================================================
 * APPROACH 5: Targeted Address Read
 *
 * After disassembling the handler dump on PC, you know exactly
 * which kernel address or CCP slot holds the key. Re-run the
 * payload with -a <address> to read from that specific location.
 *
 * Usage: ./ps5_key_extract -a 0xFFFFFFFF82345678
 *        ./ps5_key_extract -a 0xFFFFFFFF82345678 -s 256
 * ================================================================ */
static int approach5_read_address(uint64_t addr, uint32_t size) {
    printf("\n=== APPROACH 5: Targeted Address Read ===\n");
    printf("[*] Reading %u bytes from 0x%llx\n", size, (unsigned long long)addr);

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        printf("[!] malloc failed\n");
        return -1;
    }

    if (addr < 0x100000000ULL) {
        /* Physical address — use MMIO mapping */
        printf("[*] Address looks physical, using mmap\n");
        int dmem_fd = open("/dev/dmem0", O_RDWR);
        if (dmem_fd < 0) {
            printf("[!] Cannot open /dev/dmem0\n");
            free(buf);
            return -1;
        }

        void *mapped = mmap(NULL, size, PROT_READ, MAP_SHARED,
                            dmem_fd, (off_t)addr);
        if (mapped == MAP_FAILED) {
            printf("[!] mmap failed\n");
            close(dmem_fd);
            free(buf);
            return -1;
        }

        memcpy(buf, mapped, size);
        munmap(mapped, size);
        close(dmem_fd);
    } else {
        /* Kernel virtual address — use kernel_copyout */
        printf("[*] Address looks virtual, using kernel_copyout\n");
        if (kernel_copyout(addr, buf, size) != 0) {
            printf("[!] kernel_copyout failed\n");
            free(buf);
            return -1;
        }
    }

    hexdump("address read", buf, size);
    output_add_section(SECTION_ADDR_READ, buf, size);

    free(buf);
    printf("[+] Saved to dump file\n");
    return 0;
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    printf("=== PS5 PUP Key Extractor v2 ===\n");
    printf("Target: PUP header decryption key\n");
    printf("Output: /data/pup_key_dump.bin\n\n");

    /* Parse arguments */
    uint64_t target_addr = 0;
    uint32_t target_size = 4096;
    int addr_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            target_addr = strtoull(argv[++i], NULL, 0);
            addr_mode = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            target_size = (uint32_t)strtoul(argv[++i], NULL, 0);
            if (target_size > 65536) target_size = 65536;
        }
    }

    output_begin();

    if (addr_mode) {
        /* Targeted read mode — just read the specified address */
        approach5_read_address(target_addr, target_size);
    } else {
        /* Full scan mode — run all approaches */
        int r1 = approach1_ccp_lsb_dump();
        int r2 = approach2_ioctl_handler_scan();
        int r3 = approach3_instrumented_decrypt();
        int r4 = approach4_kernel_memscan();

        printf("\n=== Summary ===\n");
        printf("Approach 1 (CCP LSB + queue regs): %s\n", r1 == 0 ? "OK" : "FAILED");
        printf("Approach 2 (full handler dump):     %s\n", r2 == 0 ? "OK" : "FAILED");
        printf("Approach 3 (instrumented decrypt):  %s\n", r3 == 0 ? "OK" : "FAILED");
        printf("Approach 4 (kernel mem scan):       %s\n", r4 == 0 ? "OK" : "FAILED");
        printf("\nChained strategy:\n");
        printf("  1. Load d_ioctl/d_open dumps into Ghidra/IDA on PC\n");
        printf("  2. Find which CCP slot or kernel address the key comes from\n");
        printf("  3. Re-run with: ./ps5_key_extract -a <address> -s <size>\n");
    }

    output_write("/data/pup_key_dump.bin");

    printf("\n[*] Done. Transfer /data/pup_key_dump.bin to PC and run:\n");
    printf("    python analyze_dump.py pup_key_dump.bin\n");
    return 0;
}
