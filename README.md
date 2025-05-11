# 🧠 PDF Memory Dumper for Windows

This Python script scans the memory of a target Windows process (by PID), detects embedded PDF file data in memory, and dumps complete PDF files to disk. It uses low-level Windows APIs via `ctypes`.

## 🚀 Features

- Scans committed, readable memory regions of a running process.
- Detects PDF headers (`%PDF-x.y`) and trailers (`%%EOF`) to extract full PDF content.
- Automatically filters valid PDFs (with `/Pages` marker and size threshold).
- Saves results to a specified output directory.

## ⚙️ Requirements

- Windows OS
- Python 3.12+
- Admin privileges (or access rights to target process)
- Optional: [`psutil`](https://pypi.org/project/psutil/) (for process listing)

## 🧾 How It Works

1. Opens the target process using Win32 API with full access rights.
2. Iterates through all memory regions using `VirtualQueryEx`.
3. Reads readable memory chunks using `ReadProcessMemory`.
4. Searches for PDF signatures.
5. If a valid PDF structure is found (including `/Pages`), writes it to a `.pdf` file.

## 🛠 Configuration

Edit the top of the script to match your use case:

```python
PID = 2016                # Target process ID
OUT_DIR = 'pdf_dumps'     # Output directory for dumped PDFs
MIN_SIZE_KB = 100         # Minimum size to consider a valid PDF
MAX_BUF_MB = 100          # Max buffer size for region streaming
````

> You can use the `psutil` snippet at the bottom of the script to help find a process PID.

## 📦 Usage

1. Make sure the script is run as an administrator (if needed).
2. Replace the `PID` in the script with your target process's PID.
3. Run the script:

```bash
python pdf_dumper.py
```

4. Extracted PDFs will be saved in the `OUT_DIR` directory.

## 🧪 Example Output

```
✅ Saved pdf_dumps/dump_0.pdf (139584 bytes)
✅ Saved pdf_dumps/dump_1.pdf (87299 bytes)
⏭ Skipped fragment (95123 bytes)
🎉 Done: 2 PDF(s) dumped into 'pdf_dumps/'
```

## ⚠️ Disclaimer

* This script is for **educational and forensic purposes only**.
* Do not use on processes without permission.
* Improper use may violate software terms or laws.

## 📄 License

MIT License
