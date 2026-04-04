# GRIDLAND - Real Security Scanner

This project is a no-nonsense, effective network security scanner for identifying and assessing network cameras and other devices. It is designed for authorized penetration testing and security auditing.

The core philosophy of this tool is to **build things that work.** It prioritizes real functionality over marketing buzzwords and complex, unnecessary frameworks.

## Features

- **Web-Based UI:** A simple, real-time web interface to run scans and view results as they are discovered.
- **Powerful CLI:** A comprehensive command-line interface for advanced users and automation, based on the proven logic of `CamXploit.py`.
- **Multi-threaded Scanning:** High-performance, multi-threaded port scanning.
- **Device Fingerprinting:** Identifies common camera brands (Hikvision, Dahua, Axis, etc.).
- **Credential Testing:** Aggressively tests for default and common credentials on discovered devices.
- **Stream Discovery:** Scans for open RTSP and HTTP video streams.

## Installation

1.  Clone the repository.
2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

There are two ways to use Gridland: the Web UI (recommended for most users) and the Command-Line Interface (CLI).

### Web UI

The web UI provides a simple way to run scans and see live results.

1.  **Start the server:**
    ```bash
    flask --app server run --port 5001
    ```
2.  **Access the UI:**
    Open your web browser and navigate to `http://127.0.0.1:5001`.

3.  **Run a scan:**
    - Enter a target IP address (e.g., `192.168.1.100`) or a network range in CIDR notation (e.g., `192.168.1.0/24`).
    - Click "Start Scan".
    - Watch the results appear in real-time in the "Results" table and the "Raw Scan Log".

### Command-Line Interface (CLI)

The `gridland_clean.py` script provides a powerful command-line interface for more advanced use cases.

**Basic Scan:**
```bash
python gridland_clean.py scan <TARGET_IP_OR_CIDR>
```

**Aggressive Scan:**
Includes credential testing and stream discovery.
```bash
python gridland_clean.py scan <TARGET_IP_OR_CIDR> --aggressive
```

**Quick Scan (Single Target):**
An alias for an aggressive scan on a single target.
```bash
python gridland_clean.py quick <TARGET_IP>
```

**Options:**
- `--threads <NUM>` or `-t <NUM>`: Set the number of concurrent scanning threads (default: 100).
- `--output <FILENAME>.json` or `-o <FILENAME>.json`: Save the results to a JSON file.

**Example:**
```bash
python gridland_clean.py scan 192.168.1.0/24 --aggressive -t 200 -o scan_results.json
```
---
*This tool is intended for authorized security auditing and penetration testing purposes only. Use responsibly.*
