# Virus Scanner

A browser extension that automatically scans downloaded files for malware.

## Features

- **Auto-scan** - Scans every download automatically
- **All file types** - PDFs, images, videos, executables, torrents, etc.
- **Notifications** - Alerts when threats detected
- **Risk Score** - Shows how safe/risky each file is
- **ML Training** - Train your own model with custom datasets

## How It Works

1. Download starts → Extension detects new file
2. Quick analysis:
   - File extension risk level
   - Filename patterns
   - Known legitimate software
3. Shows risk score and explanation

## Installation (Chrome/Edge)

1. Open Chrome/Edge → `chrome://extensions/`
2. Enable **Developer mode** (top-right)
3. Click **Load unpacked**
4. Select `browser_extension/` folder

## Training Your Own Model

### Step 1: Add Dataset Files

Create a folder structure like this:
```
datasets/
├── clean/          ← Add legitimate software here
├── trojan/          ← Add trojan samples here
├── worm/            ← Add worm samples here
├── ransomware/      ← Add ransomware samples here
├── spyware/         ← Add spyware samples here
├── adware/          ← Add adware samples here
├── backdoor/        ← Add backdoor samples here
├── dropper/         ← Add dropper samples here
└── pup/            ← Add PUP samples here
```

### Step 2: Get Malware Samples

Download from:
- VirusShare (virus-share.com)
- MalwareBazaar (malwarebazaar.com)
- VX-Underground (vx-underground.org)
- Contagio Malware Dump

### Step 3: Train the Model

```bash
# Install dependencies
pip install numpy scikit-learn

# Train model
python train_model.py

# Test model on a file
python train_model.py -t path/to/file.exe
```

### Step 4: Update Extension

After training, the model will be saved as `trained_model.pkl`.
Copy it to the `browser_extension/` folder and reload the extension.

## Files

- `virsus.py` - Python CLI scanner
- `train_model.py` - ML model trainer
- `browser_extension/` - Chrome/Edge extension
- `datasets/` - Training data folder

## Settings

- **Auto-scan**: On/Off auto-scanning
- **Notifications**: Show/hide alerts

## Risk Levels

- **Safe (0-5%)** - Images, documents, known software
- **Low (5-20%)** - Archives, scripts
- **Medium (20-35%)** - Executables, installers
- **Dangerous (60%+)** - Crack, patch, keygen files
