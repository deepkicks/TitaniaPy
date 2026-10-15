# PUP Container Key Extraction — Step-by-Step Guide

This guide walks through the full process of extracting the missing PUP container decryption key from a jailbroken PS5 on FW 13.60 or below. The person with console access needs to run the payload at most twice. Everything else happens on PC.

**Risk level: Zero.** The payload is completely read-only — no writes to kernel, hardware, flash, or NVS. See the FAQ at the bottom.

---

## Phase 1: On the PS5 (the person with console access)

### Step 1 — Set up the jailbreak

Boot the PS5 on FW 13.60. Open the browser, navigate to the exploit host (e.g. the etaHEN page), run the Relapse kernel exploit, then Byepervisor Reborn. The console now has kernel R/W.

### Step 2 — Compile the payload

On a PC, cross-compile `ps5_key_extract.c` for FreeBSD 11 amd64:

```bash
clang -target x86_64-unknown-freebsd11 -o ps5_key_extract ps5_key_extract.c
```

You'll need to link your framework's `kernel_read64`, `kernel_read32`, and `kernel_copyout` implementations. These are typically provided by the payload SDK (e.g. etaHEN/GoldHEN SDK).

### Step 3 — Load and run the payload

Send the compiled binary to the PS5 via the payload loader (usually TCP port 9020):

```bash
nc 192.168.1.XX 9020 < ps5_key_extract
```

The payload runs all 5 approaches automatically. Console screen or log output shows progress. Takes about 10-30 seconds.

### Step 4 — Transfer the dump file

Use FTP (etaHEN enables FTP on port 2121):

```bash
ftp 192.168.1.XX 2121
> get /data/pup_key_dump.bin
> bye
```

The file is typically 50-200KB depending on how many sections were captured. Send this file to whoever is doing the PC-side analysis.

---

## Phase 2: First Analysis Pass (on PC)

### Step 5 — Run the analyzer

```bash
pip install -r requirements.txt
python analyze_dump.py pup_key_dump.bin --pup14 PS5UPDATE14.00.PUP --pup14_1 PS5UPDATE14.10.PUP
```

Example output:

```
[+] Dump version 2, 8 sections
  Section 0: CCP LSB Key Slots, 4096 bytes at offset 0x440
  Section 1: CCP Queue Registers, 220 bytes at offset 0x1440
  Section 2: cdevsw Struct, 128 bytes at offset 0x1518
  Section 3: d_ioctl Handler Code, 16384 bytes at offset 0x1598
  Section 4: d_open Handler Code, 16384 bytes at offset 0x5598
  ...

--- CCP Queue Registers ---
  Queue 0:
    PUBLIC_MASK_LO       = 0x0000ffff
    PRIVATE_MASK_LO      = 0x0000ff00
    CPU-readable slots mask: 0x00000000000000ff
    [+] Slot 0 is CPU-readable
    [+] Slot 1 is CPU-readable
    ...

--- cdevsw Struct (pup_update0) ---
  +0x10 d_open           = 0xffffffff8234a000
  +0x30 d_ioctl          = 0xffffffff8234b200

[*] Extracted 47 unique key candidates
[*] Testing 47 candidates against 2 PUP files...
```

**If the output says `KEY FOUND`** — skip to Phase 4. You're done.

**If no match (most likely)** — continue to Phase 3. This is expected — it means the key is in a hardware-protected CCP slot or loaded from an address we need to find by reading the handler code.

---

## Phase 3: Reverse Engineer the Handler (on PC)

This is where the chained strategy pays off. The dump contains 16KB of the raw x86-64 code that implements `DecryptPupHeader`. We disassemble it to find where the key comes from.

### Step 6 — Extract the handler binaries

Save this as `quick_extract.py` and run it:

```python
import struct
from pathlib import Path

data = Path("pup_key_dump.bin").read_bytes()
magic, ver, count = struct.unpack_from("<QII", data, 0)

section_names = {
    0x02: "d_ioctl",
    0x09: "d_open",
    0x0A: "d_close",
    0x06: "cdevsw",
}

for i in range(count):
    off = 16 + i * 16
    stype, ssize, soffset, _ = struct.unpack_from("<IIII", data, off)
    if stype in section_names:
        name = section_names[stype]
        blob = data[soffset:soffset + ssize]
        outfile = f"{name}.bin"
        Path(outfile).write_bytes(blob)
        print(f"Wrote {outfile} ({ssize} bytes)")
```

```bash
python quick_extract.py
# Output:
# Wrote d_ioctl.bin (16384 bytes)
# Wrote d_open.bin (16384 bytes)
# Wrote d_close.bin (16384 bytes)
# Wrote cdevsw.bin (128 bytes)
```

### Step 7 — Load into Ghidra (or IDA)

1. Open Ghidra, create a new project
2. Import `d_ioctl.bin` as **Raw Binary**, language **x86:LE:64:default**
3. Set the base address to the `d_ioctl` address from the cdevsw output (e.g. `0xffffffff8234b200`)
4. Run Auto Analysis
5. Repeat for `d_open.bin` using its address from the cdevsw output

### Step 8 — What to look for

You're looking for how the key gets loaded into the CCP for the AES decrypt operation. Common patterns in the disassembly:

**Pattern A — Key loaded from a kernel memory address:**
```asm
mov rdi, 0xffffffff82XXXXXX    ; <-- THIS is the key address
call ccp_enqueue_aes_cmd
```
This is the best case. The key sits at a fixed kernel address and we can read it directly.

**Pattern B — Key referenced by CCP slot number:**
```asm
mov dword [rsp+0x10], 7        ; key_id = slot 7
mov dword [rsp+0x14], 0        ; AES-128-CBC mode
call ccp_submit_request
```
Check whether that slot showed up as CPU-readable in the queue register output from step 5.

**Pattern C — Key unwrapped from another slot:**
```asm
mov edi, 5                     ; source slot (wrapped key)
mov esi, 3                     ; wrapping key slot
call ccp_key_unwrap
```
More complex — need to find both the wrapped key and the wrapping key.

**What to grep for in the disassembly:**
- Constants 0 or 1 (AES engine type = 0, CBC mode = 1)
- Small integers 0-127 (CCP slot numbers)
- Addresses starting with `0xffffffff8` (kernel pointers)
- Function names containing `ccp`, `sbl`, `encsrv`, `crypto`, `aes`
- The constant `0xC0184402` (the ioctl number — trace backward from where it's dispatched)

### Step 9 — Get the key based on what you found

**If it's a kernel virtual address** (starts with `0xffffffff`):

Have the PS5 person re-run the payload with a targeted read:
```bash
./ps5_key_extract -a 0xffffffff82XXXXXX -s 256
```
Then FTP the new `pup_key_dump.bin` to PC and re-run `analyze_dump.py`.

**If it's a CCP slot number:**

Check the queue register output from step 5:
- Slot IS in the CPU-readable mask → the key should already be in the LSB dump. Re-check the candidates.
- Slot is NOT CPU-readable → need to find where the key was loaded FROM (look at the code that runs before the CCP command is submitted).

**If it's a physical MMIO address:**
```bash
./ps5_key_extract -a 0xE01XXXXX -s 64
```

---

## Phase 4: Verify the Key

### Step 10 — Test the candidate

Run the analyzer again with the new dump:

```bash
python analyze_dump.py pup_key_dump.bin --pup14 PS5UPDATE14.00.PUP --pup14_1 PS5UPDATE14.10.PUP
```

If the key is correct, you'll see:

```
[!!!] MATCH on FW 14.00 (CBC)!
      file_size=0x4b2339d5 (diff=0 from BLS 0x4b2339d5)
      segment_count=44
      Full decrypted: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[!!!] MATCH on FW 14.10 (CBC)!
      file_size=0x4b2f8a3d (diff=0 from BLS 0x4b2f8a3d)
      segment_count=44

KEY FOUND: a1b2c3d4e5f67890...
Source: Targeted Address Read @ offset 0x0
```

A match on BOTH firmware versions confirms this is the universal PUP container key.

### Step 11 — Add it to the tool

Open `keys.py` and add the key:

```python
PUP_CONTAINER_KEY = bytes.fromhex("a1b2c3d4e5f67890...")
```

Update `crypto.py` to use it in the decrypt pipeline. The tool now decrypts every PUP from every firmware version. Done forever.

---

## Quick Reference: What the PS5 Person Does

| Run | Command | Time | What it does |
|-----|---------|------|-------------|
| 1 | `./ps5_key_extract` | ~30 sec | Full scan — dumps handler code + LSB slots + registers |
| 2 (maybe) | `./ps5_key_extract -a 0x... -s 256` | ~5 sec | Targeted read of specific address found during RE |

Then FTP the dump file to PC after each run. That's it.

---

## FAQ

**Can this brick the PS5?**
No. The payload is completely read-only. It reads kernel memory and hardware registers. It does not write to kernel memory, flash, NVS, syscon, or any hardware state. The only write is a regular file to `/data/pup_key_dump.bin`.

**Does the jailbreak need to be persistent?**
No. The exploit runs in RAM. The payload executes while the exploit is active, saves the dump to the filesystem, and you transfer it via FTP. The dump file survives reboot even though the jailbreak doesn't.

**What if approach 1 returns all zeros for LSB slots?**
Expected — those slots are likely hardware-protected (private mask set). That's why approach 2 (handler dump) is the primary strategy. The handler code tells you WHERE the key comes from, so you can target that source directly.

**What if I can't find the key pattern in Ghidra?**
Share the `d_ioctl.bin` and `d_open.bin` files with the community. Multiple eyes on the disassembly will find it faster. The cdevsw addresses help calibrate the analysis.

**What firmware versions does the key work for?**
All of them — past and future. The PUP container key is universal (every console uses the same one) and permanent (burned into ROM/silicon since FW 1.0). It cannot be rotated without bricking every PS5 ever made.
