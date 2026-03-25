# winters — Malware Scanner

> A browser extension that automatically scans downloaded files for malware using heuristic analysis and a trainable ML model.

![Platform](https://img.shields.io/badge/platform-Chrome%20%7C%20Edge-blue?style=flat-square)
![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Features

| Feature | Description |
|---|---|
| Auto-scan | Automatically scans every download |
| All file types | PDFs, images, videos, executables, torrents, and more |
| Notifications | Real-time alerts when threats are detected |
| Risk Score | Displays a risk percentage with explanation |
| ML Training | Train a custom model on your own dataset |

---

## How It Works

1. A download is detected by the extension
2. The file is analyzed using:
   - File extension risk classification
   - Filename pattern matching
   - Known legitimate software allowlist
3. A risk score (0–100%) is returned with a verdict

---

## Installation

**Requirements:** Chrome or Edge with Developer Mode enabled

1. Navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `browser_extension/` folder

---

## Training a Custom Model

### 1. Prepare the Dataset

Organize samples into the following structure:

```
datasets/
├── clean/        ← Legitimate software
├── trojan/
├── worm/
├── ransomware/
├── spyware/
├── adware/
├── backdoor/
├── dropper/
└── pup/          ← Potentially Unwanted Programs
```

**Sample sources:**
- [VirusShare](https://virusshare.com)
- [MalwareBazaar](https://bazaar.abuse.ch)
- [VX-Underground](https://vx-underground.org)
- Contagio Malware Dump

### 2. Train the Model

```bash
# Install dependencies
pip install numpy scikit-learn

# Train
python train_model.py

# Test on a specific file
python train_model.py -t path/to/file.exe
```

### 3. Deploy to Extension

After training, copy `trained_model.pkl` into `browser_extension/` and reload the extension.

---

## Project Structure

```
virsu/
├── virsus.py              # Python CLI scanner
├── train_model.py         # ML model trainer
├── browser_extension/     # Chrome/Edge extension
└── datasets/              # Training data
```

---

## Risk Levels

| Level | Range | Examples |
|---|---|---|
| Safe | 0 – 5% | Images, documents, known software |
| Low | 5 – 20% | Archives, scripts |
| Medium | 20 – 35% | Executables, installers |
| Dangerous | 60%+ | Cracks, keygens, patches |

---

## Settings

- **Auto-scan** — Toggle automatic scanning on/off
- **Notifications** — Show or hide threat alerts
