/*
 * ps5_key_extract.c — PUP header decryption key extractor for jailbroken PS5
 *
 * Target: PS5 FW 13.60 or below with kernel R/W (e.g. Byepervisor Reborn + Relapse)
 * Build: compile for FreeBSD 11 amd64, load via payload loader
 * Output: /data/pup_key_dump.bin (structured binary with section headers)
 *
 * All operations are READ-ONLY. Nothing is written to kernel or hardware state.
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

/* ---------- output format ---------- */
#define DUMP_MAGIC       0x505550444D50ULL  /* "PUPDMP\0\0" */
#define SECTION_LSB      0x01
#define SECTION_IOCTL    0x02
#define SECTION_SNAP_PRE 0x03
#define SECTION_SNAP_POST 0x04
#define SECTION_MEMSCAN  0x05

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
#define PCI_VENDOR_AMD       0x1022
#define CCP_DEV_ID_1         0x1456
#define CCP_DEV_ID_2         0x1468
#define CCP_DEV_ID_3         0x15DF

#define CCP_QUEUE_MMIO_BASE  0x3001000
#define CCP_QUEUE_STRIDE     0x1000

/* LSB mask register offsets within a queue */
#define CCP_PUBLIC_MASK_LO   0x18
#define CCP_PUBLIC_MASK_HI   0x1C
#define CCP_PRIVATE_MASK_LO  0x20
#define CCP_PRIVATE_MASK_HI  0x24

/* Candidate LSB region offsets from CCP BAR */
#define LSB_OFFSET_A         0x8000
#define LSB_OFFSET_B         0x10000
#define LSB_OFFSET_C         0x4000

/* LSB geometry: 8 LSBs x 16 slots x 32 bytes = 4096 bytes */
#define LSB_COUNT            8
#define SLOTS_PER_LSB        16
#define SLOT_SIZE            32
#define LSB_TOTAL_SIZE       (LSB_COUNT * SLOTS_PER_LSB * SLOT_SIZE)

/* CCP engine type constants (from Linux ccp-dev.h) */
#define CCP_ENGINE_AES       0
#define CCP_ENGINE_XTS_AES   1
#define CCP_ENGINE_DES3       2 /* 3DES */
#define CCP_ENGINE_SHA       3
#define CCP_ENGINE_RSA       4
#define CCP_ENGINE_PASSTHRU  5
#define CCP_ENGINE_ZLIB      6
#define CCP_ENGINE_ECC       7

/* CCP AES modes */
#define CCP_AES_MODE_ECB     0
#define CCP_AES_MODE_CBC     1
#define CCP_AES_MODE_OFB     2
#define CCP_AES_MODE_CFB     3
#define CCP_AES_MODE_CTR     4
#define CCP_AES_MODE_CMAC    5
#define CCP_AES_MODE_GHASH   6
#define CCP_AES_MODE_GCTR    7
#define CCP_AES_MODE_GCM     8
#define CCP_AES_MODE_GMAC    9

/* ---------- PUP ioctl constants (from psdevwiki) ---------- */
#define PUP_DEVICE_PATH      "/dev/pup_update0"
#define PUP_IOCTL_DECRYPT_HEADER  0xC0184402  /* DecryptPupHeader */
#define PUP_IOCTL_VERIFY_SEGMENT  0xC0184403
#define PUP_IOCTL_DECRYPT_SEGMENT 0xC0184404
#define PUP_HEADER_ENC_SIZE       0x5B0

/* ---------- PS5 kernel constants (FreeBSD 11 based) ---------- */
#define KERNEL_BASE_PRIMARY   0xFFFFFFFF82200000ULL
#define KERNEL_BASE_FALLBACK  0xFFFFFFFF80000000ULL

/* FreeBSD 11 cdevsw field offsets */
#define CDEVSW_D_VERSION     0x00
#define CDEVSW_D_NAME        0x08
#define CDEVSW_D_OPEN        0x10
#define CDEVSW_D_CLOSE       0x18
#define CDEVSW_D_READ        0x20
#define CDEVSW_D_WRITE       0x28
#define CDEVSW_D_IOCTL       0x30
#define CDEVSW_D_POLL        0x38

/* ioctl argument for DecryptPupHeader */
typedef struct {
    uint64_t src_paddr;
    uint64_t dst_paddr;
    uint32_t size;
    uint32_t flags;
} __attribute__((packed)) pup_decrypt_arg_t;

/* ---------- globals ---------- */
static uint8_t  g_output[256 * 1024];
static uint32_t g_output_pos = 0;
static uint32_t g_section_count = 0;

static section_header_t g_sections[32];

/* ---------- output helpers ---------- */
static void output_begin(void) {
    g_output_pos = sizeof(dump_header_t) + sizeof(g_sections);
    g_section_count = 0;
    memset(g_output, 0, sizeof(g_output));
}

static void output_add_section(uint32_t type, const void *data, uint32_t size) {
    if (g_section_count >= 32) return;
    if (g_output_pos + size > sizeof(g_output)) return;

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
    hdr.version = 1;
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
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && (i % 16) == 0) printf("\n");
        if ((i % 16) == 0) printf("    %04zx: ", i);
        printf("%02x ", data[i]);
    }
    printf("\n");
}

/* ================================================================
 * APPROACH 1: CCP LSB Key Slot Dump
 *
 * Map the AMD CCP v5 MMIO region and read all 128 LSB key slots.
 * The CCP stores AES keys used by the security processor in its
 * Local Storage Block (LSB). The PUP decrypt key should be in one
 * of these slots.
 * ================================================================ */
static int approach1_ccp_lsb_dump(void) {
    printf("\n=== APPROACH 1: CCP LSB Key Slot Dump ===\n");

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

    /* Find CCP BAR via PCI config space scan */
    uint64_t ccp_bar = 0;
    printf("[*] Scanning PCI for AMD CCP (vendor 0x%04x, devices 0x%04x/0x%04x/0x%04x)...\n",
           PCI_VENDOR_AMD, CCP_DEV_ID_1, CCP_DEV_ID_2, CCP_DEV_ID_3);

    /*
     * PCI config space on x86: use I/O ports 0xCF8/0xCFC or ECAM.
     * On PS5, the CCP is integrated into the SoC. Try known MMIO bases.
     * The queue MMIO base 0x3001000 is relative to the CCP BAR.
     * Typical PS5 CCP BAR candidates:
     */
    uint64_t bar_candidates[] = {
        0xE0100000ULL,  /* common AMD APU CCP BAR */
        0xFED80000ULL,  /* AMD FCH region */
        0xFEC10000ULL,
        0x03000000ULL,  /* from dayzerosec: queue base 0x3001000 implies BAR ~ 0x3000000 */
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

            /* Check for non-zero slots */
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

        /* Also read the queue mask registers */
        for (int q = 0; q < 5; q++) {
            uint64_t queue_base = bar + CCP_QUEUE_MMIO_BASE + (q * CCP_QUEUE_STRIDE);
            void *qmap = mmap(NULL, 0x100, PROT_READ, MAP_SHARED,
                              dmem_fd, (off_t)queue_base);
            if (qmap == MAP_FAILED) continue;

            uint32_t pub_lo  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PUBLIC_MASK_LO);
            uint32_t pub_hi  = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PUBLIC_MASK_HI);
            uint32_t priv_lo = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PRIVATE_MASK_LO);
            uint32_t priv_hi = *(volatile uint32_t *)((uint8_t *)qmap + CCP_PRIVATE_MASK_HI);
            munmap(qmap, 0x100);

            if (pub_lo || pub_hi || priv_lo || priv_hi) {
                printf("[+] Queue %d masks: pub=0x%08x%08x priv=0x%08x%08x\n",
                       q, pub_hi, pub_lo, priv_hi, priv_lo);
            }
        }
    }

    close(dmem_fd);
    if (!found_any) {
        printf("[!] No non-zero LSB data found via MMIO\n");
    }
    return found_any ? 0 : -1;
}

/* ================================================================
 * APPROACH 2: EncryptService ioctl Handler Scan
 *
 * Find the pup_update device's cdevsw in kernel memory, extract
 * the d_ioctl handler pointer, dump 4KB of the handler code.
 * This is the function called by ioctl 0xC0184402.
 * ================================================================ */
static int approach2_ioctl_handler_scan(void) {
    printf("\n=== APPROACH 2: EncryptService ioctl Handler Scan ===\n");

    uint64_t kernel_bases[] = { KERNEL_BASE_PRIMARY, KERNEL_BASE_FALLBACK };
    const char *search_str = "pup_update";
    size_t search_len = strlen(search_str);

    /* Scan range: first 32MB of kernel text/data */
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

        /* Search for "pup_update" string */
        for (size_t i = 0; i < scan_size - search_len; i++) {
            if (memcmp(&kbuf[i], search_str, search_len) == 0 && kbuf[i + search_len] == '\0') {
                uint64_t str_kaddr = kbase + i;
                printf("[+] Found \"%s\" at kernel address 0x%llx\n",
                       search_str, (unsigned long long)str_kaddr);

                /*
                 * Now search for a pointer to this string in kernel memory.
                 * In FreeBSD 11 cdevsw, d_name is at offset 0x08.
                 * So cdevsw_base = ptr_location - 0x08.
                 */
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

                        /* Read d_ioctl at cdevsw + 0x30 */
                        uint64_t d_ioctl = kernel_read64(cdevsw_base + CDEVSW_D_IOCTL);
                        printf("[+] d_ioctl handler at 0x%llx\n",
                               (unsigned long long)d_ioctl);

                        /* Validate: should be in kernel space */
                        if (d_ioctl < 0xFFFFFFFF80000000ULL) {
                            printf("[!] d_ioctl address looks invalid, skipping\n");
                            continue;
                        }

                        /* Also read other cdevsw entries for context */
                        uint64_t d_open  = kernel_read64(cdevsw_base + CDEVSW_D_OPEN);
                        uint64_t d_close = kernel_read64(cdevsw_base + CDEVSW_D_CLOSE);
                        printf("[*] d_open=0x%llx d_close=0x%llx\n",
                               (unsigned long long)d_open,
                               (unsigned long long)d_close);

                        /* Dump 4KB of the ioctl handler code */
                        uint8_t handler_code[4096];
                        if (kernel_copyout(d_ioctl, handler_code, sizeof(handler_code)) == 0) {
                            printf("[+] Dumped ioctl handler (4096 bytes)\n");
                            hexdump("ioctl handler first 128 bytes", handler_code, 128);
                            output_add_section(SECTION_IOCTL, handler_code, sizeof(handler_code));
                        } else {
                            printf("[!] Failed to dump ioctl handler code\n");
                        }

                        /* Dump the cdevsw struct itself */
                        uint8_t cdevsw_raw[0x80];
                        if (kernel_copyout(cdevsw_base, cdevsw_raw, sizeof(cdevsw_raw)) == 0) {
                            hexdump("cdevsw struct", cdevsw_raw, sizeof(cdevsw_raw));
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
 * Strategy: take a snapshot of all CCP LSB key slots BEFORE and
 * AFTER issuing the DecryptPupHeader ioctl. Any slot that changed
 * from zero to non-zero (or changed value) during the call was
 * loaded by the security processor for the decryption — that's
 * our key candidate.
 *
 * This requires a real PUP header blob to be present at a known
 * physical address. The caller must arrange DMA-able memory.
 * ================================================================ */
static int approach3_instrumented_decrypt(void) {
    printf("\n=== APPROACH 3: Instrumented PUP Decrypt ===\n");

    int pup_fd = open(PUP_DEVICE_PATH, O_RDWR);
    if (pup_fd < 0) {
        printf("[!] Cannot open %s — device may not exist or access denied\n",
               PUP_DEVICE_PATH);
        printf("[*] Strategy: snapshot LSB before/after ioctl 0x%x\n",
               PUP_IOCTL_DECRYPT_HEADER);
        printf("[*] The ioctl argument is 24 bytes:\n");
        printf("[*]   uint64_t src_paddr  — physical address of encrypted header\n");
        printf("[*]   uint64_t dst_paddr  — physical address for decrypted output\n");
        printf("[*]   uint32_t size       — 0x5B0 (PUP header encrypted size)\n");
        printf("[*]   uint32_t flags      — typically 0\n");
        printf("[*] The key is loaded into a CCP LSB slot during the ioctl call.\n");
        printf("[*] Compare pre/post LSB snapshots to identify which slot changed.\n");
        return -1;
    }

    printf("[+] Opened %s\n", PUP_DEVICE_PATH);

    /* Take pre-decrypt LSB snapshot via MMIO */
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

    /*
     * Issue the decrypt ioctl.
     * NOTE: src/dst must be valid physical addresses containing
     * a real encrypted PUP header. This is a placeholder —
     * a real implementation must allocate contiguous physical
     * memory (e.g. via contigmalloc or /dev/dmem0).
     */
    printf("[*] To actually invoke the ioctl, provide valid src/dst paddrs.\n");
    printf("[*] Skipping actual ioctl call (would need DMA-able memory with PUP header).\n");

    /* Take post-decrypt snapshot */
    memcpy(post_lsb, mapped, LSB_TOTAL_SIZE);
    munmap(mapped, LSB_TOTAL_SIZE);
    printf("[+] Post-decrypt LSB snapshot captured\n");
    output_add_section(SECTION_SNAP_POST, post_lsb, LSB_TOTAL_SIZE);

    /* Diff the snapshots */
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
 * Strings: "encsrv", "encrypt_service", "pup_key",
 *          "decrypt_header", "ccp_key"
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

                    /* Dump 512 bytes of surrounding context */
                    size_t ctx_start = (i >= 256) ? (i - 256) : 0;
                    size_t ctx_end = i + 256;
                    if (ctx_end > scan_size) ctx_end = scan_size;
                    size_t ctx_len = ctx_end - ctx_start;

                    char label[128];
                    snprintf(label, sizeof(label), "context around \"%s\"", needles[n]);
                    hexdump(label, &kbuf[ctx_start], ctx_len);

                    output_add_section(SECTION_MEMSCAN, &kbuf[ctx_start], (uint32_t)ctx_len);
                    total_found++;

                    /* Skip past this match to avoid duplicates */
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

/* ---------- main ---------- */
int main(int argc, char **argv) {
    printf("=== PS5 PUP Key Extractor ===\n");
    printf("Target: PUP header decryption key (AES-128)\n");
    printf("Output: /data/pup_key_dump.bin\n\n");

    output_begin();

    int r1 = approach1_ccp_lsb_dump();
    int r2 = approach2_ioctl_handler_scan();
    int r3 = approach3_instrumented_decrypt();
    int r4 = approach4_kernel_memscan();

    printf("\n=== Summary ===\n");
    printf("Approach 1 (CCP LSB dump):       %s\n", r1 == 0 ? "OK" : "FAILED");
    printf("Approach 2 (ioctl handler scan):  %s\n", r2 == 0 ? "OK" : "FAILED");
    printf("Approach 3 (instrumented decrypt):%s\n", r3 == 0 ? "OK" : "FAILED");
    printf("Approach 4 (kernel mem scan):     %s\n", r4 == 0 ? "OK" : "FAILED");

    output_write("/data/pup_key_dump.bin");

    printf("\n[*] Done. Transfer /data/pup_key_dump.bin to PC and run analyze_dump.py\n");
    return 0;
}
