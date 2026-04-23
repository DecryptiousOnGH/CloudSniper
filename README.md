# CloudSniper

**Author:** Decryptious_ on Discord / Punchborn on IG  
**License:** MIT  
**Platforms:** Linux, Windows, macOS

A cross-platform cloud storage reconnaissance tool that hunts for misconfigured AWS S3 buckets, Azure Blob containers, and Google Cloud Storage buckets.

---

## Features

- **Multi-Cloud Support:** AWS S3, Azure Blob Storage, GCP Storage
- **Intelligent Permutations:** Auto-generates bucket/container names from target domain
- **Certificate Transparency:** Scans crt.sh for cloud references in SSL certificates
- **Permission Detection:** Identifies listable, public, restricted, and redirect responses
- **Multi-threaded:** Configurable thread pool for fast scanning
- **Export Reports:** Saves results to both `.txt` and `.json`
- **Cross-Platform:** Works on Linux, Windows, and macOS terminals

---

Installation

Method 1: Clone and Run

git clone https://github.com/DecryptiousOnGH/CloudSniper
cd CloudSniper
pip install -r requirements.txt
python3 cloudsniper.py -u example.com

Method 2: Direct Download (No Git)

# Linux/macOS
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/CloudSniper/main/cloudsniper.py
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/CloudSniper/main/requirements.txt
pip install -r requirements.txt
python3 cloudsniper.py -u example.com

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/CloudSniper/main/cloudsniper.py" -OutFile "cloudsniper.py"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/CloudSniper/main/requirements.txt" -OutFile "requirements.txt"
pip install -r requirements.txt
python cloudsniper.py -u example.com

Method 3: System Install

pip install .
cloudsniper -u example.com

Usage

Scan All Cloud Services
python3 cloudsniper.py -u example.com

Scan Only AWS S3
python3 cloudsniper.py -u example.com -s aws

Scan AWS and Azure
python3 cloudsniper.py -u example.com -s aws azure

Fast Scan (50 threads)
python3 cloudsniper.py -u example.com -t 50

Save to Specific File
python3 cloudsniper.py -u example.com -o myscan.txt

Verbose Mode
python3 cloudsniper.py -u example.com -v

Options

| Flag             | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| `-u, --url`      | **Required.** Target domain                                    |
| `-s, --services` | Services to check: `aws`, `azure`, `gcp`, `all` (default: all) |
| `-t, --threads`  | Thread count (default: 20)                                     |
| `--timeout`      | Request timeout in seconds (default: 15)                       |
| `-o, --output`   | Output filename                                                |
| `-v, --verbose`  | Show failed requests                                           |
| `--no-banner`    | Hide startup banner                                            |
