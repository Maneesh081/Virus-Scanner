#!/usr/bin/env python3
"""
Virus Scanner - ML Model Trainer
Trains a model using training/malware/ and training/clean/ folders
Generates SHAP explanations and auto-copies to browser_extension/
"""

import os
import sys
import json
import math
import struct
import pickle
import shutil
import re
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

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    print("Installing SHAP...")
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', 'shap'])
    import shap
    SHAP_AVAILABLE = True

VERSION = "1.0"

# Feature names for SHAP explanations
FEATURE_NAMES = [
    'file_size', 'file_size_kb', 'file_size_mb', 'is_large_file', 'is_small_file',
    'entropy', 'high_entropy', 'medium_entropy', 'low_entropy',
    'is_pe', 'is_x86', 'is_x64', 'num_sections', 'pe_timestamp', 'pe_flag1',
    'pe_flag2', 'pe_flag3', 'pe_flag4', 'pe_flag5', 'pe_flag6',
    'import_count', 'import_count_high', 'import_count_very_high', 'import_count_extreme',
    'import_flag1', 'import_flag2', 'import_flag3', 'import_flag4', 'import_flag5', 'import_flag6',
    'import_flag7', 'import_flag8', 'import_flag9', 'import_flag10', 'import_flag11',
    'url_count', 'ip_count', 'suspicious_strings', 'suspicious_strings_flag', 'base64_count',
    'section_text', 'section_data', 'section_rsrc', 'section_reloc', 'section_upx0',
    'section_aspack', 'section_packed', 'section_stub', 'section_flag9', 'section_flag10'
]

# Suspicious imports
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
        except Exception:
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
        return -sum((c / len(sample)) * math.log2(c / len(sample)) for c in freq.values() if c > 0)

    def _analyze_pe(self, data):
        """Analyze PE header"""
        features = [0] * 15

        if len(data) < 64 or data[:2] != b'MZ':
            return features

        try:
            features[0] = 1  # Is PE
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            if pe_offset + 24 < len(data):
                machine = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
                features[1] = 1 if machine == 0x014C else 0  # x86
                features[2] = 1 if machine == 0x8664 else 0  # x64
                features[3] = struct.unpack('<H', data[pe_offset + 6:pe_offset + 8])[0]
        except Exception:
            pass

        return features

    def _analyze_imports(self, data):
        """Analyze suspicious imports"""
        features = [0] * 20

        try:
            text = data.decode('utf-8', errors='ignore').lower()
        except Exception:
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
        except Exception:
            return features

        urls = len(re.findall(r'https?://\S+', text))
        ips = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
        features[0] = urls
        features[1] = ips

        suspicious_count = sum(1 for s in SUSPICIOUS_STRINGS if s.lower() in text.lower())
        features[2] = suspicious_count
        features[3] = 1 if suspicious_count > 3 else 0

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
        self.X_train = None
        self.feature_names = FEATURE_NAMES

    def load_dataset(self, dataset_path):
        """Load files from training/malware/ and training/clean/ folders"""
        X = []
        y = []

        malware_dir = Path(dataset_path) / 'malware'
        clean_dir = Path(dataset_path) / 'clean'

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
                y.append(1)  # malware
            except Exception as e:
                print(f"    Error: {file_path.name} - {e}")

        # Load clean samples
        clean_files = [f for f in clean_dir.iterdir() if f.is_file() and not f.name.startswith('.')]
        print(f"  Clean samples: {len(clean_files)}")

        for file_path in clean_files:
            try:
                features = self.extractor.extract(str(file_path))
                X.append(features)
                y.append(0)  # clean
            except Exception as e:
                print(f"    Error: {file_path.name} - {e}")

        if not X:
            print("\nNo files found!")
            print("\nPlease add files to:")
            print(f"  {malware_dir} - for malware samples")
            print(f"  {clean_dir} - for clean samples")
            return None, None

        print(f"\nTotal samples: {len(X)} (Malware: {sum(y)}, Clean: {len(y) - sum(y)})")
        return np.array(X), np.array(y)

    def train(self, X, y):
        """Train the model"""
        print("\nTraining model...")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.X_train = X_train

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

    def generate_shap_explanations(self):
        """Generate SHAP explanations and export to JSON"""
        if self.model is None:
            print("No model trained!")
            return None

        print("\nGenerating SHAP explanations...")

        try:
            # Use TreeExplainer for Random Forest
            explainer = shap.TreeExplainer(self.model)

            # Get SHAP values for a subset of training data
            sample_size = min(100, len(self.X_train))
            X_sample = self.X_train[:sample_size]

            shap_values = explainer.shap_values(X_sample)

            # For binary classification, shap_values is a list [class_0, class_1]
            # We use class_1 (malware) values
            if isinstance(shap_values, list):
                malware_shap = shap_values[1]
            else:
                malware_shap = shap_values

            # Calculate mean absolute SHAP values for each feature
            mean_shap = np.abs(malware_shap).mean(axis=0)

            # Get top features that indicate malware
            top_malware_idx = np.argsort(mean_shap)[-10:][::-1]
            top_clean_idx = np.argsort(mean_shap)[:10]

            # Build explanations
            malware_explanations = {}
            clean_explanations = {}

            # Feature descriptions for human-readable explanations
            feature_descriptions = {
                'file_size': 'File size is suspicious',
                'entropy': 'High entropy (packed/encrypted content)',
                'high_entropy': 'Very high entropy detected',
                'medium_entropy': 'Elevated entropy level',
                'is_pe': 'Windows executable file',
                'import_count': 'Many suspicious API imports',
                'import_count_high': 'High number of dangerous imports',
                'url_count': 'Contains embedded URLs',
                'ip_count': 'Contains embedded IP addresses',
                'suspicious_strings': 'Suspicious code patterns found',
                'suspicious_strings_flag': 'Multiple suspicious patterns',
                'base64_count': 'Contains encoded strings',
                'section_upx0': 'Packed with UPX',
                'section_packed': 'Contains packed sections',
                'is_small_file': 'Very small file size'
            }

            clean_descriptions = {
                'file_size': 'Normal file size',
                'low_entropy': 'Low entropy (uncompressed)',
                'is_pe': 'Standard executable format',
                'import_count': 'Normal API usage',
                'section_text': 'Contains code section',
                'section_data': 'Contains data section',
                'section_rsrc': 'Contains resources',
                'section_reloc': 'Standard relocation section'
            }

            # Generate malware reason explanations
            malware_reasons = []
            for idx in top_malware_idx:
                if idx < len(self.feature_names):
                    fname = self.feature_names[idx]
                    if fname in feature_descriptions:
                        malware_reasons.append(feature_descriptions[fname])
                    elif 'import' in fname.lower():
                        malware_reasons.append('Suspicious API calls detected')
                    elif 'section' in fname.lower():
                        malware_reasons.append('Suspicious PE section')
                    elif 'pe' in fname.lower():
                        malware_reasons.append('PE header anomaly')

            # Generate clean reason explanations
            clean_reasons = []
            for idx in top_clean_idx:
                if idx < len(self.feature_names):
                    fname = self.feature_names[idx]
                    if fname in clean_descriptions:
                        clean_reasons.append(clean_descriptions[fname])

            # Build final explanations object
            explanations = {
                'version': VERSION,
                'generated_at': datetime.now().isoformat(),
                'malware_reasons': malware_reasons[:5],
                'clean_reasons': clean_reasons[:5],
                'top_malware_features': [self.feature_names[i] for i in top_malware_idx if i < len(self.feature_names)][:10],
                'top_clean_features': [self.feature_names[i] for i in top_clean_idx if i < len(self.feature_names)][:10],
                'feature_importance': {
                    self.feature_names[i]: float(mean_shap[i])
                    for i in range(len(mean_shap))
                    if i < len(self.feature_names)
                }
            }

            print(f"  Malware indicators: {malware_reasons[:3]}")
            print(f"  Clean indicators: {clean_reasons[:3]}")

            return explanations

        except Exception as e:
            print(f"SHAP generation failed: {e}")
            print("Using fallback explanations...")

            # Fallback explanations without SHAP
            return {
                'version': VERSION,
                'generated_at': datetime.now().isoformat(),
                'malware_reasons': [
                    'High entropy (packed/encrypted content)',
                    'Suspicious API calls detected',
                    'Contains embedded URLs or IP addresses',
                    'Multiple suspicious code patterns',
                    'PE header anomalies detected'
                ],
                'clean_reasons': [
                    'Normal file entropy',
                    'Standard API usage patterns',
                    'No suspicious strings detected',
                    'Standard executable format',
                    'Known legitimate software pattern'
                ],
                'top_malware_features': ['entropy', 'import_count', 'url_count', 'suspicious_strings', 'section_packed'],
                'top_clean_features': ['low_entropy', 'import_count', 'section_text', 'section_data', 'is_pe'],
                'feature_importance': {}
            }

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

    def save_explanations(self, explanations, extension_dir):
        """Save explanations JSON to browser extension folder"""
        if explanations is None:
            print("No explanations to save!")
            return False

        dest = Path(extension_dir) / 'explanations.json'
        with open(dest, 'w') as f:
            json.dump(explanations, f, indent=2)

        print(f"Explanations copied to extension: {dest}")
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

    # Generate SHAP explanations
    explanations = trainer.generate_shap_explanations()

    # Save to training folder
    output_path = Path(__file__).parent / 'trained_model.pkl'
    trainer.save_model(output_path)

    # Auto-copy to browser extension
    extension_dir = Path(__file__).parent / 'browser_extension'
    if extension_dir.exists():
        trainer.copy_to_extension(output_path, extension_dir)
        trainer.save_explanations(explanations, extension_dir)

    print("\n" + "=" * 50)
    print("Training Complete!")
    print("=" * 50)
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Model saved to: {output_path}")
    print(f"Model copied to: {extension_dir}/trained_model.pkl")
    print(f"Explanations copied to: {extension_dir}/explanations.json")
    print("\nReload the extension to use the new model!")


if __name__ == '__main__':
    main()