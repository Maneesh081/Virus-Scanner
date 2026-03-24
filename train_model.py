#!/usr/bin/env python3
"""
Virus Scanner - ML Model Trainer
Trains a model using training/malware/ and training/clean/ folders
"""

import os
import sys
import json
import math
import struct
import pickle
import shutil
from collections import Counter
from pathlib import Path
from datetime import datetime

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', 'numpy', 'scikit-learn'])
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

VERSION = "1.0"

# Suspicious imports to look for
SUSPICIOUS_IMPORTS = [
    'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 
    'OpenProcess', 'GetProcAddress', 'LoadLibrary', 'CreateProcess',
    'ShellExecute', 'WinExec', 'NtQuerySystemInformation',
    'NtWriteVirtualMemory', 'NtReadVirtualMemory',
    'CreateService', 'AdjustTokenPrivileges', 'RegSetValueEx',
    'FindWindow', 'SetWindowsHook', 'GetAsyncKeyState',
    'InternetOpen', 'InternetOpenUrl', 'HttpSendRequest',
    'socket', 'connect', 'send', 'recv',
    'URLDownloadToFile', 'CryptEncrypt', 'BCryptEncrypt'
]

SUSPICIOUS_STRINGS = [
    'https://', 'http://', '192.168.', '10.0.', '172.16.',
    'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'schtasks', 'cmd.exe', 'powershell',
    'encrypt', 'ransom', 'bitcoin', 'payment',
    'keylog', 'backdoor', 'reverse', 'shell', 'meterpreter',
    'download', 'execute', 'runas'
]

class FeatureExtractor:
    """Extract features from files for ML training"""
    
    def extract(self, file_path):
        """Extract features from a file"""
        features = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            return [0] * 100
        
        # File size features
        file_size = len(data)
        features.append(file_size)
        features.append(file_size / 1024)
        features.append(file_size / (1024 * 1024))
        features.append(1 if file_size > 1024 * 1024 else 0)
        features.append(1 if file_size < 1024 else 0)
        
        # Entropy
        entropy = self._calc_entropy(data)
        features.append(entropy)
        features.append(1 if entropy > 7.5 else 0)
        features.append(1 if entropy > 6.5 else 0)
        features.append(1 if entropy < 4 else 0)
        
        # PE header features
        features.extend(self._analyze_pe(data))
        
        # Import analysis
        features.extend(self._analyze_imports(data))
        
        # String patterns
        features.extend(self._analyze_strings(data))
        
        # Section analysis
        features.extend(self._analyze_sections(data))
        
        # Pad to 100 features
        while len(features) < 100:
            features.append(0)
        
        return features[:100]
    
    def _calc_entropy(self, data):
        """Calculate Shannon entropy"""
        if len(data) < 256:
            return 0
        sample = data[:10000]
        freq = Counter(sample)
        return -sum((c/len(sample)) * math.log2(c/len(sample)) for c in freq.values() if c > 0)
    
    def _analyze_pe(self, data):
        """Analyze PE header"""
        features = [0] * 15
        
        if len(data) < 64 or data[:2] != b'MZ':
            return features
        
        try:
            features[0] = 1  # Is PE
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_offset + 24 < len(data):
                machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
                features[1] = 1 if machine == 0x014C else 0  # x86
                features[2] = 1 if machine == 0x8664 else 0  # x64
                features[3] = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]  # num sections
        except:
            pass
        
        return features
    
    def _analyze_imports(self, data):
        """Analyze suspicious imports"""
        features = [0] * 20
        
        try:
            text = data.decode('utf-8', errors='ignore').lower()
        except:
            return features
        
        count = 0
        for imp in SUSPICIOUS_IMPORTS:
            if imp.lower() in text:
                count += 1
        
        features[0] = count
        features[1] = 1 if count > 5 else 0
        features[2] = 1 if count > 10 else 0
        features[3] = 1 if count > 15 else 0
        
        return features
    
    def _analyze_strings(self, data):
        """Analyze suspicious strings"""
        features = [0] * 15
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            return features
        
        import re
        
        # URLs and IPs
        urls = len(re.findall(r'https?://\S+', text))
        ips = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
        features[0] = urls
        features[1] = ips
        
        # Suspicious strings count
        suspicious_count = sum(1 for s in SUSPICIOUS_STRINGS if s.lower() in text.lower())
        features[2] = suspicious_count
        features[3] = 1 if suspicious_count > 3 else 0
        
        # Base64
        features[4] = len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text))
        
        return features
    
    def _analyze_sections(self, data):
        """Analyze PE sections"""
        features = [0] * 10
        section_names = [b'.text', b'.data', b'.rsrc', b'.reloc', b'.upx0', 
                        b'.aspack', b'.packed', b'.stub']
        for i, name in enumerate(section_names):
            features[i] = 1 if name in data else 0
        return features


class ModelTrainer:
    """Train ML model from datasets"""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        self.model = None
    
    def load_dataset(self, dataset_path):
        """Load files from training/malware/ and training/clean/ folders"""
        X = []
        y = []
        
        malware_dir = Path(dataset_path) / 'malware'
        clean_dir = Path(dataset_path) / 'clean'
        
        # Create directories if they don't exist
        malware_dir.mkdir(parents=True, exist_ok=True)
        clean_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\nLoading dataset from: {dataset_path}")
        
        # Load malware samples
        malware_files = [f for f in malware_dir.iterdir() if f.is_file() and not f.name.startswith('.')]
        print(f"  Malware samples: {len(malware_files)}")
        
        for file_path in malware_files:
            try:
                features = self.extractor.extract(str(file_path))
                X.append(features)
                y.append(1)  # 1 = malware
            except Exception as e:
                print(f"    Error: {file_path.name} - {e}")
        
        # Load clean samples
        clean_files = [f for f in clean_dir.iterdir() if f.is_file() and not f.name.startswith('.')]
        print(f"  Clean samples: {len(clean_files)}")
        
        for file_path in clean_files:
            try:
                features = self.extractor.extract(str(file_path))
                X.append(features)
                y.append(0)  # 0 = clean
            except Exception as e:
                print(f"    Error: {file_path.name} - {e}")
        
        if not X:
            print("\nNo files found!")
            print("\nPlease add files to:")
            print(f"  {malware_dir} - for malware samples")
            print(f"  {clean_dir} - for clean samples")
            return None, None
        
        print(f"\nTotal samples: {len(X)} (Malware: {sum(y)}, Clean: {len(y)-sum(y)})")
        return np.array(X), np.array(y)
    
    def train(self, X, y):
        """Train the model"""
        print("\nTraining model...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nAccuracy: {accuracy:.2%}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Clean', 'Malware']))
        
        return accuracy
    
    def save_model(self, output_path):
        """Save trained model"""
        if self.model is None:
            print("No model to save!")
            return False
        
        model_data = {
            'model': self.model,
            'version': VERSION,
            'trained_at': datetime.now().isoformat(),
            'feature_count': 100
        }
        
        with open(output_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"\nModel saved to: {output_path}")
        return True
    
    def copy_to_extension(self, model_path, extension_dir):
        """Copy model to browser extension folder"""
        dest = Path(extension_dir) / 'trained_model.pkl'
        shutil.copy2(model_path, dest)
        print(f"Model copied to extension: {dest}")
        return True


def main():
    print("=" * 50)
    print("Virus Scanner - ML Model Trainer")
    print("=" * 50)
    
    trainer = ModelTrainer()
    
    # Use training folder
    dataset_path = Path(__file__).parent / 'training'
    
    X, y = trainer.load_dataset(dataset_path)
    
    if X is None or len(X) == 0:
        return
    
    # Train
    accuracy = trainer.train(X, y)
    
    # Save to training folder
    output_path = Path(__file__).parent / 'trained_model.pkl'
    trainer.save_model(output_path)
    
    # Auto-copy to browser extension
    extension_dir = Path(__file__).parent / 'browser_extension'
    if extension_dir.exists():
        trainer.copy_to_extension(output_path, extension_dir)
    
    print("\n" + "=" * 50)
    print("Training Complete!")
    print("=" * 50)
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Model saved to: {output_path}")
    print(f"Model copied to: {extension_dir}/trained_model.pkl")
    print("\nReload the extension to use the new model!")


if __name__ == '__main__':
    main()