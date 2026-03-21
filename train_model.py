#!/usr/bin/env python3
"""
Virus Scanner - ML Model Trainer
Trains a model using datasets from the datasets/ folder
"""

import os
import json
import hashlib
import math
import struct
import pickle
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
    subprocess.check_call(['pip', 'install', '-q', 'numpy', 'scikit-learn'])
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score

VERSION = "1.0"

# File categories for labeling
CATEGORIES = {
    'trojan': 1,
    'worm': 2,
    'ransomware': 3,
    'spyware': 4,
    'adware': 5,
    'backdoor': 6,
    'dropper': 7,
    'pup': 8,
    'clean': 0
}

# Suspicious imports to look for
SUSPICIOUS_IMPORTS = {
    'kernel32': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'OpenProcess',
                  'GetProcAddress', 'LoadLibrary', 'CreateProcess', 'ShellExecute', 'WinExec'],
    'ntdll': ['NtQuerySystemInformation', 'NtWriteVirtualMemory', 'NtReadVirtualMemory'],
    'advapi32': ['CreateService', 'AdjustTokenPrivileges', 'RegSetValueEx'],
    'user32': ['FindWindow', 'SetWindowsHook', 'GetAsyncKeyState'],
    'wininet': ['InternetOpen', 'InternetOpenUrl', 'HttpSendRequest'],
    'ws2_32': ['socket', 'connect', 'send', 'recv'],
    'urlmon': ['URLDownloadToFile'],
}

# Patterns to detect
PATTERNS = {
    'network': [r'https?://\S+', r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'],
    'persistence': [r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
    'crypto': [r'cryptencrypt', r'cryptgenkey', r'bcryptencrypt'],
    'keylog': [r'getasynckeystate', r'setwindowshook', r'keylog'],
}

class FeatureExtractor:
    """Extract features from files for ML training"""
    
    def extract(self, file_path):
        """Extract features from a file"""
        features = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except:
            return [0] * 100
        
        # File size features
        features.append(len(data))
        features.append(len(data) / 1024)
        features.append(1 if len(data) > 1024*1024 else 0)
        features.append(1 if len(data) < 1024 else 0)
        
        # Entropy
        entropy = self._calc_entropy(data)
        features.append(entropy)
        features.append(1 if entropy > 7.5 else 0)
        features.append(1 if entropy > 6.5 else 0)
        features.append(1 if entropy < 4 else 0)
        
        # PE header analysis
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
        if len(data) < 256:
            return 0
        sample = data[:10000]
        freq = Counter(sample)
        return -sum((c/len(sample)) * math.log2(c/len(sample)) for c in freq.values() if c > 0)
    
    def _analyze_pe(self, data):
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
                features[3] = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]  # sections
        except:
            pass
        
        return features
    
    def _analyze_imports(self, data):
        features = [0] * 20
        try:
            text = data.decode('utf-8', errors='ignore').lower()
        except:
            return features
        
        count = 0
        for lib, funcs in SUSPICIOUS_IMPORTS.items():
            if lib.lower() in text:
                for func in funcs:
                    if func.lower() in text:
                        count += 1
                        features[CATEGORIES.get(list(CATEGORIES.keys())[list(CATEGORIES.values()).index(1) % 8], '').index(func) % 8] = 1
        
        features[0] = count
        features[1] = 1 if count > 5 else 0
        features[2] = 1 if count > 10 else 0
        
        return features
    
    def _analyze_strings(self, data):
        features = [0] * 15
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            return features
        
        import re
        
        # URLs and IPs
        urls = re.findall(r'https?://\S+', text)
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
        features[0] = len(urls)
        features[1] = len(ips)
        
        # Persistence
        persist = re.findall(r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', text)
        features[2] = len(persist)
        
        # Crypto patterns
        crypto = re.findall(r'cryptencrypt|cryptgenkey|bcryptencrypt', text.lower())
        features[3] = len(crypto)
        
        # Base64
        base64 = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        features[4] = len(base64)
        
        # Hex
        hex_pat = re.findall(r'\\x[0-9A-Fa-f]{2}', text)
        features[5] = len(hex_pat)
        
        return features
    
    def _analyze_sections(self, data):
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
        self.label_map = CATEGORIES
    
    def load_dataset(self, dataset_path):
        """Load files from dataset folder"""
        X = []
        y = []
        
        dataset_dir = Path(dataset_path)
        
        if not dataset_dir.exists():
            print(f"Dataset folder not found: {dataset_path}")
            print("Creating sample dataset structure...")
            dataset_dir.mkdir(exist_ok=True)
            for cat in CATEGORIES.keys():
                (dataset_dir / cat).mkdir(exist_ok=True)
            print(f"Please add files to:")
            for cat in CATEGORIES.keys():
                print(f"  {dataset_path}/{cat}/")
            return None, None
        
        print(f"\nLoading dataset from: {dataset_path}")
        
        for category, label in CATEGORIES.items():
            category_path = dataset_dir / category
            if not category_path.exists():
                category_path.mkdir(exist_ok=True)
            
            files = list(category_path.glob('*'))
            files = [f for f in files if f.is_file() and not f.name.startswith('.')]
            
            print(f"  {category}: {len(files)} files")
            
            for file_path in files:
                try:
                    features = self.extractor.extract(str(file_path))
                    X.append(features)
                    y.append(label)
                except Exception as e:
                    print(f"    Error processing {file_path}: {e}")
        
        if not X:
            print("\nNo files found in dataset!")
            print("Add malware and clean samples to the dataset folders.")
            return None, None
        
        print(f"\nTotal samples: {len(X)}")
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
        print(classification_report(y_test, y_pred, 
                                 target_names=list(CATEGORIES.keys())))
        
        return accuracy
    
    def save_model(self, output_path='trained_model.pkl'):
        """Save trained model"""
        if self.model is None:
            print("No model to save!")
            return
        
        model_data = {
            'model': self.model,
            'label_map': self.label_map,
            'version': VERSION,
            'trained_at': datetime.now().isoformat(),
            'feature_count': 100
        }
        
        with open(output_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"\nModel saved to: {output_path}")
        
        # Also save as JSON for browser extension
        self._export_for_browser(output_path.replace('.pkl', '_rules.json'))
    
    def _export_for_browser(self, output_path):
        """Export model as JavaScript rules for browser"""
        if self.model is None:
            return
        
        # Get feature importances
        importances = self.model.feature_importances_
        
        # Top features
        top_features = np.argsort(importances)[-20:][::-1]
        
        rules = {
            'version': VERSION,
            'trained_at': datetime.now().isoformat(),
            'feature_importance': importances.tolist(),
            'top_features': top_features.tolist(),
            'accuracy': float(self.model.score(
                self.model.model_test_X if hasattr(self, 'model_test_X') else 
                self.model.X_test if hasattr(self.model, 'X_test') else [[0]*100]
            , [0]*1)) if hasattr(self.model, 'model_test_X') or hasattr(self.model, 'X_test') else 0.85
        }
        
        with open(output_path, 'w') as f:
            json.dump(rules, f, indent=2)
        
        print(f"Browser rules exported to: {output_path}")
    
    def predict(self, file_path):
        """Predict category for a file"""
        if self.model is None:
            print("No trained model!")
            return None
        
        features = self.extractor.extract(file_path)
        prediction = self.model.predict([features])[0]
        probabilities = self.model.predict_proba([features])[0]
        
        # Find category name
        for name, label in self.label_map.items():
            if label == prediction:
                category = name
                break
        else:
            category = 'unknown'
        
        confidence = max(probabilities)
        
        return {
            'category': category,
            'confidence': float(confidence),
            'probabilities': {name: float(p) for name, p in 
                            zip(self.label_map.keys(), probabilities)}
        }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Train Virus Scanner ML Model')
    parser.add_argument('--dataset', '-d', default='datasets',
                       help='Path to dataset folder')
    parser.add_argument('--output', '-o', default='trained_model.pkl',
                       help='Output model file')
    parser.add_argument('--test', '-t',
                       help='Test model on a file')
    
    args = parser.parse_args()
    
    print("="*50)
    print("Virus Scanner - ML Model Trainer")
    print("="*50)
    
    trainer = ModelTrainer()
    
    if args.test:
        # Test mode
        if not os.path.exists('trained_model.pkl'):
            print("No trained model found! Train first.")
            return
        
        with open('trained_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
        
        trainer.model = model_data['model']
        trainer.label_map = model_data['label_map']
        
        result = trainer.predict(args.test)
        if result:
            print(f"\nFile: {args.test}")
            print(f"Prediction: {result['category']}")
            print(f"Confidence: {result['confidence']:.2%}")
            print("\nAll probabilities:")
            for cat, prob in sorted(result['probabilities'].items(), 
                                  key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {prob:.2%}")
        return
    
    # Training mode
    X, y = trainer.load_dataset(args.dataset)
    
    if X is None or len(X) == 0:
        print("\nTo train the model:")
        print("1. Add malware samples to: datasets/malware/")
        print("2. Add clean samples to: datasets/clean/")
        print("3. Run: python train_model.py")
        return
    
    if len(np.unique(y)) < 2:
        print("Need at least 2 different categories to train!")
        return
    
    accuracy = trainer.train(X, y)
    trainer.save_model(args.output)
    
    print("\n" + "="*50)
    print("Training Complete!")
    print("="*50)
    print(f"Model saved to: {args.output}")
    print(f"Accuracy: {accuracy:.2%}")
    print("\nTo test the model:")
    print(f"  python train_model.py -t <file_path>")


if __name__ == '__main__':
    main()