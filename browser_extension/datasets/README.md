# VIRSUS Datasets

This folder is for malware datasets to train the ML model.

## How to Add Data

### Option 1: Add malware samples
- Create folders for each category:
  - `malware/trojan/`
  - `malware/worm/`
  - `malware/ransomware/`
  - `malware/spyware/`
  - `malware/adware/`
  - `malware/backdoor/`

### Option 2: Add clean samples
- Create `clean/` folder with legitimate software samples

### Dataset Format
- Place raw executable files (.exe, .dll)
- Each file will be processed to extract features

## Training
Run `python train_model.py` to train on your datasets.

## Recommended Sources
- VirusShare
- MalwareBazaar
- VX-Underground
- Contagio Malware Dump