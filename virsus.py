#!/usr/bin/env python3
"""
VIRSUS - Malware Detection System
Detects Trojans, worms, ransomware, spyware, adaware, backdoors
"""

import os
import sys
import re
import json
import math
import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import List, Dict

VERSION = "1.0.0"

@dataclass
class Finding:
    category: str
    severity: str
    description: str
    evidence: List[str]

@dataclass
class AnalysisResult:
    file_path: str
    file_hash: str
    file_size: int
    risk_score: int
    threat_category: str
    confidence: float
    severity: str
    findings: List[Finding]
    recommendations: List[str]


class MalwareDetector:
    """Main malware detection engine"""
    
    SUSPICIOUS_IMPORTS = {
        'kernel32': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 
                     'OpenProcess', 'GetProcAddress', 'LoadLibrary'],
        'wininet': ['InternetOpen', 'InternetOpenUrl', 'InternetReadFile', 'HttpSendRequest'],
        'ws2_32': ['socket', 'connect', 'send', 'recv', 'listen', 'accept'],
        'advapi32': ['CreateService', 'AdjustTokenPrivileges', 'RegSetValueEx'],
        'user32': ['FindWindow', 'SetWindowsHook', 'GetAsyncKeyState'],
        'urlmon': ['URLDownloadToFile'],
    }

    NETWORK_PATTERNS = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    ]
    
    PERSISTENCE_PATTERNS = [
        r'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        r'schtasks\s+/create',
    ]
    
    MALWARE_SIGNATURES = {
        'ransomware': ['encrypt', 'ransom', 'bitcoin', 'payment'],
        'keylogger': ['keylog', 'getasynckeystate', 'setwindowshook'],
        'backdoor': ['reverse', 'shell', 'bind', 'meterpreter'],
        'worm': ['spread', 'replicate', 'propagate', 'network'],
    }
    
    KNOWN_CLEAN_URLS = ['microsoft.com', 'vscode', 'github', 'cdn', 'visualstudio', 
                        'npmjs', 'pypi', 'python.org', 'google', 'cloudflare', 'amazonaws']
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.indicators: Dict = {}
        
    def analyze_file(self, file_path: str) -> AnalysisResult:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        
        text_content = ""
        try:
            text_content = raw_data.decode('utf-8', errors='ignore')
        except:
            pass
        
        self.findings = []
        self.indicators = {'imports': [], 'network': [], 'persistence': False, 
                          'entropy': 0, 'obfuscation': []}
        
        self._analyze_imports(text_content)
        self._analyze_strings(text_content)
        self._analyze_entropy(raw_data)
        self._analyze_obfuscation(text_content)
        
        risk_score = self._calculate_score()
        threat, confidence = self._classify()
        severity = self._get_severity(risk_score, threat)
        recommendations = self._get_recommendations(threat, risk_score)
        
        return AnalysisResult(
            file_path=file_path,
            file_hash=hashlib.sha256(raw_data).hexdigest(),
            file_size=len(raw_data),
            risk_score=risk_score,
            threat_category=threat,
            confidence=confidence,
            severity=severity,
            findings=self.findings,
            recommendations=recommendations
        )
    
    def _analyze_imports(self, text: str):
        detected = []
        for lib, funcs in self.SUSPICIOUS_IMPORTS.items():
            if lib.lower() in text.lower():
                for func in funcs:
                    if func.lower() in text.lower():
                        detected.append(f"{lib}.{func}")
        
        self.indicators['imports'] = detected
        if len(detected) >= 3:
            self.findings.append(Finding(
                category="Suspicious Imports",
                severity="critical",
                description=f"Found {len(detected)} dangerous API functions",
                evidence=detected[:8]
            ))
        elif detected:
            self.findings.append(Finding(
                category="Suspicious Imports", 
                severity="medium",
                description=f"Found {len(detected)} potentially dangerous APIs",
                evidence=detected[:5]
            ))
    
    def _analyze_strings(self, text: str):
        network_ips = set()
        persistence_found = False
        
        for pattern in self.NETWORK_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                if not any(clean in m.lower() for clean in self.KNOWN_CLEAN_URLS):
                    network_ips.add(m)
        
        for pattern in self.PERSISTENCE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                persistence_found = True
                break
        
        for category, sigs in self.MALWARE_SIGNATURES.items():
            for sig in sigs:
                if re.search(sig, text, re.IGNORECASE):
                    self.findings.append(Finding(
                        category=f"{category.title()} Signature",
                        severity="critical",
                        description=f"Detected {category} behavior pattern",
                        evidence=[sig]
                    ))
        
        self.indicators['network'] = list(network_ips)
        self.indicators['persistence'] = persistence_found
        
        if network_ips:
            self.findings.append(Finding(
                category="Network Indicators",
                severity="high",
                description=f"Found {len(network_ips)} suspicious network indicators",
                evidence=list(network_ips)[:5]
            ))
    
    def _analyze_entropy(self, data: bytes):
        if len(data) < 256:
            return
            
        sample = data[:10000]
        freq = Counter(sample)
        entropy = -sum((c/len(sample)) * math.log2(c/len(sample)) 
                      for c in freq.values() if c > 0)
        
        self.indicators['entropy'] = entropy
        
        if entropy > 7.5:
            self.findings.append(Finding(
                category="High Entropy (Packed/Encrypted)",
                severity="high",
                description=f"Entropy {entropy:.2f} suggests packed/encrypted code",
                evidence=[f"Entropy: {entropy:.2f}/8.0"]
            ))
    
    def _analyze_obfuscation(self, text: str):
        patterns = []
        
        if len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)) > 5:
            patterns.append("Base64 strings")
        if len(re.findall(r'\\x[0-9A-Fa-f]{2}', text)) > 10:
            patterns.append("Hex-encoded bytes")
        if 'xor' in text.lower():
            patterns.append("XOR operations")
        
        if patterns:
            self.indicators['obfuscation'] = patterns
            self.findings.append(Finding(
                category="Code Obfuscation",
                severity="high",
                description="Multiple obfuscation techniques detected",
                evidence=patterns
            ))
    
    def _calculate_score(self) -> int:
        score = 0
        
        critical = sum(1 for f in self.findings if f.severity == "critical")
        high = sum(1 for f in self.findings if f.severity == "high")
        medium = sum(1 for f in self.findings if f.severity == "medium")
        
        score += critical * 25
        score += high * 15
        score += medium * 8
        score += len(self.indicators['imports']) * 5
        
        if self.indicators['persistence']:
            score += 20
        
        if self.indicators['entropy'] > 7.5:
            score += 20
        
        if not self.findings:
            score = 5
            
        return min(max(score, 0), 100)
    
    def _classify(self):
        critical_count = sum(1 for f in self.findings if f.severity == "critical")
        
        if critical_count >= 2:
            return "trojan", 0.85
        elif critical_count == 1 and len(self.indicators['imports']) >= 3:
            return "trojan", 0.7
        elif self.indicators['persistence']:
            return "adware", 0.5
        elif self.findings:
            return "suspicious", 0.4
            
        return "clean", 0.9
    
    def _get_severity(self, score, threat):
        if threat == "clean":
            return "safe"
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
    
    def _get_recommendations(self, threat, score):
        if threat == "clean" or score < 20:
            return ["File appears clean", "Continue normal usage"]
        
        recs = ["ISOLATE: Quarantine this file", "SCAN: Run full system antivirus"]
        
        if threat in ["trojan", "backdoor"]:
            recs.extend(["CHECK: Review network connections", "SCAN: Check for injected processes"])
        if threat == "ransomware":
            recs.extend(["BACKUP: Verify backup integrity", "DISCONNECT: Isolate from network"])
            
        return recs


class ReportFormatter:
    """Format analysis results"""
    
    COLORS = {
        'critical': '\033[91m',
        'high': '\033[93m', 
        'medium': '\033[95m',
        'low': '\033[92m',
        'safe': '\033[94m',
        'endc': '\033[0m'
    }
    
    @staticmethod
    def print_terminal(result):
        print(f"\n{'='*60}")
        print(f"  VIRSUS - Malware Detection v{VERSION}")
        print(f"{'='*60}")
        
        print(f"\nFile: {result.file_path}")
        print(f"Size: {result.file_size:,} bytes")
        print(f"SHA256: {result.file_hash[:32]}...")
        
        print(f"\n{'-'*60}")
        
        color = ReportFormatter.COLORS.get(result.severity, '')
        endc = ReportFormatter.COLORS['endc']
        
        print(f"  Risk Score: {color}{result.risk_score}/100{endc}")
        print(f"  Severity:    {color}{result.severity.upper()}{endc}")
        print(f"  Category:    {color}{result.threat_category.upper()}{endc}")
        print(f"  Confidence:  {color}{result.confidence*100:.1f}%{endc}")
        
        if result.findings:
            print(f"\n{'-'*60}")
            print(f"  FINDINGS ({len(result.findings)} detected)")
            print(f"{'-'*60}")
            
            for i, f in enumerate(result.findings, 1):
                sev_color = ReportFormatter.COLORS.get(f.severity, '')
                print(f"\n  {i}. [{sev_color}{f.severity.upper()}{endc}] {f.category}")
                print(f"     {f.description}")
                if f.evidence:
                    print(f"     Evidence:")
                    for ev in f.evidence[:3]:
                        print(f"       -> {ev}")
        
        if result.recommendations:
            print(f"\n{'-'*60}")
            print(f"  RECOMMENDATIONS")
            print(f"{'-'*60}")
            for rec in result.recommendations:
                print(f"     {rec}")
        
        print(f"\n{'='*60}\n")
        
        return result.risk_score >= 50 or result.threat_category != "clean"
    
    @staticmethod
    def print_json(result):
        data = {
            'file': {
                'path': result.file_path,
                'size': result.file_size,
                'sha256': result.file_hash
            },
            'analysis': {
                'risk_score': result.risk_score,
                'severity': result.severity,
                'threat_category': result.threat_category,
                'confidence': result.confidence
            },
            'findings': [
                {
                    'category': f.category,
                    'severity': f.severity,
                    'description': f.description,
                    'evidence': f.evidence
                }
                for f in result.findings
            ],
            'recommendations': result.recommendations
        }
        print(json.dumps(data, indent=2))


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='VIRSUS - Malware Detection')
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    
    detector = MalwareDetector()
    
    try:
        result = detector.analyze_file(args.file)
        
        if args.json:
            ReportFormatter.print_json(result)
        else:
            is_malicious = ReportFormatter.print_terminal(result)
            sys.exit(0 if not is_malicious else 1)
            
    except Exception as e:
        print(f"Error analyzing file: {e}")
        sys.exit(2)


if __name__ == '__main__':
    main()