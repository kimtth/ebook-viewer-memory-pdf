import ctypes
import ctypes.wintypes as wintypes
import re
import os

# ─── Configuration ──────────────────────────────────────────────────────────
PID = 2016                # <--- Replace with your target process ID
OUT_DIR = 'pdf_dumps'     # Output directory for dumped PDFs
MIN_SIZE_KB = 100         # Minimum PDF size to consider (in KB)
MAX_BUF_MB = 100          # Maximum buffer size when streaming regions (in MB)

# ─── Win32 constants & setup ────────────────────────────────────────────────
PROCESS_ALL_ACCESS     = 0x1F0FFF
MEM_COMMIT             = 0x1000
PAGE_NOACCESS          = 0x01
PAGE_GUARD             = 0x100
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_void_p),
        ('AllocationBase',    ctypes.c_void_p),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             wintypes.DWORD),
        ('Protect',           wintypes.DWORD),
        ('Type',              wintypes.DWORD),
    ]


def is_readable(protect):
    ok = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
    return (protect & ok) and not (protect & PAGE_GUARD)

# ─── Win32 function bindings ────────────────────────────────────────────────
OpenProcess       = kernel32.OpenProcess
VirtualQueryEx    = kernel32.VirtualQueryEx
ReadProcessMemory = kernel32.ReadProcessMemory
CloseHandle       = kernel32.CloseHandle


def enum_regions(pid):
    """Yield (base, size) for each committed, readable region in ascending order."""
    proc = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not proc:
        raise ctypes.WinError(ctypes.get_last_error())
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    max_addr = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8 - 1)) - 1
    while addr < max_addr:
        if not VirtualQueryEx(proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        if mbi.State == MEM_COMMIT and is_readable(mbi.Protect):
            yield (mbi.BaseAddress, mbi.RegionSize)
        addr += mbi.RegionSize
    CloseHandle(proc)


def read_region(pid, base, size):
    """Read and return bytes from [base, base+size)."""
    proc = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ReadProcessMemory(proc, ctypes.c_void_p(base), buf, size, ctypes.byref(bytes_read))
    CloseHandle(proc)
    return buf.raw[:bytes_read.value]


def dump_all_pdfs(pid, out_dir, min_size_kb, max_buf_mb):
    os.makedirs(out_dir, exist_ok=True)
    header_re = re.compile(br'%PDF-[0-9]+\.[0-9]+')
    trailer_re = re.compile(br'%%EOF\r\n?')
    regions = list(enum_regions(pid))
    dumps = 0

    for idx, (base, size) in enumerate(regions):
        data = read_region(pid, base, size)
        for header_match in header_re.finditer(data):
            start_off = header_match.start()
            buf = bytearray()
            # Stream subsequent regions into buf
            for b2, sz2 in regions[idx:]:
                chunk = read_region(pid, b2, sz2)
                if b2 == base:
                    chunk = chunk[start_off:]
                buf.extend(chunk)
                if len(buf) > max_buf_mb * 1024 * 1024:
                    break
            # Find all trailers in buf
            for trailer_match in trailer_re.finditer(buf):
                end = trailer_match.end()
                pdf_bytes = bytes(buf[:end])
                if len(pdf_bytes) >= min_size_kb * 1024 and b'/Pages' in pdf_bytes:
                    path = os.path.join(out_dir, f'dump_{dumps}.pdf')
                    with open(path, 'wb') as f:
                        f.write(pdf_bytes)
                    print(f"✅ Saved {path} ({len(pdf_bytes)} bytes)")
                    dumps += 1
                else:
                    print(f"⏭ Skipped fragment ({len(pdf_bytes)} bytes)")
    if dumps:
        print(f"🎉 Done: {dumps} PDF(s) dumped into '{out_dir}/'")
    else:
        print("❌ No full-size PDF found. Try lowering min_size_kb or increasing max_buf_mb.")

# --- Execute dump with manual configuration ---
dump_all_pdfs(PID, OUT_DIR, MIN_SIZE_KB, MAX_BUF_MB)


""" import psutil
for p in psutil.process_iter(['pid', 'name']):
    print(p.info)
 """