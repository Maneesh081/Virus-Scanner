# Virus Scanner

A browser extension that automatically scans downloaded files for malware.

## Features

- **Auto-scan** - Automatically scans the latest download
- **Quick Scan** - Manual scan button
- **Notifications** - Alerts when threats detected
- **History** - View past scan results
- **Risk Score** - Shows how safe/risky each file is

## How It Works

1. Download starts → Extension detects new file
2. Only scans latest download
3. Quick analysis:
   - File extension check
   - Filename patterns
   - Source URL analysis
4. Shows risk score and explanation

## Installation (Chrome/Edge)

### Option 1: Load Unpacked (Recommended)
1. Open Chrome/Edge → `chrome://extensions/`
2. Enable **Developer mode** (top-right)
3. Click **Load unpacked**
4. Select `browser_extension/` folder

### Option 2: GitHub
1. Download the repository as ZIP
2. Extract files
3. Load unpacked as above

## Files

- `browser_extension/` - Chrome/Edge extension files
- `virsus.py` - Python CLI tool
- `requirements.txt` - Python dependencies

## Settings

- **Auto-scan**: On/Off auto-scanning
- **Notifications**: Show/hide alerts
