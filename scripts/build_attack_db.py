#!/usr/bin/env python3
"""
Build enhanced MITRE ATT&CK database from official sources.
"""
import json
import sqlite3
import requests
from datetime import datetime
from pathlib import Path

def download_attack_data():
    """Download official MITRE ATT&CK data."""
    urls = {
        'enterprise': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        'pre-attack': 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json',
        'mobile': 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json'
    }
    
    data_dir = Path('attack_data')
    data_dir.mkdir(exist_ok=True)
    
    for name, url in urls.items():
        print(f"Downloading {name} ATT&CK data...")
        response = requests.get(url)
        response.raise_for_status()
        
        with open(data_dir / f'{name}.json', 'w') as f:
            json.dump(response.json(), f, indent=2)
    
    print("ATT&CK data downloaded successfully!")

def create_sqlite_db():
    """Create SQLite database from ATT&CK data."""
    conn = sqlite3.connect('data/attack.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS techniques (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            tactic TEXT,
            data_source TEXT,
            platforms TEXT,
            detection TEXT,
            mitigation TEXT,
            refs TEXT,
            created_at TIMESTAMP,
            modified_at TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tactics (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            data_source TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS software (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            labels TEXT,
            data_source TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            aliases TEXT,
            data_source TEXT
        )
    ''')
    
    # Load and parse ATT&CK data
    data_dir = Path('attack_data')
    for json_file in data_dir.glob('*.json'):
        with open(json_file) as f:
            data = json.load(f)
        
        # Parse techniques
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                technique_id = obj.get('id', '')
                name = obj.get('name', '')
                description = obj.get('description', '')
                
                # Extract tactics
                tactics = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name'))
                
                # Extract platforms
                platforms = ', '.join(obj.get('x_mitre_platforms', []))
                
                # Extract detection and mitigation
                detection = ''
                mitigation = ''
                for mitigation_obj in obj.get('x_mitre_detection', []):
                    detection += mitigation_obj.get('description', '') + '\n'
                
                for mitigation_obj in obj.get('x_mitre_mitigation', []):
                    mitigation += mitigation_obj.get('description', '') + '\n'
                
                # Extract references
                references = []
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        references.append(ref.get('url'))
                
                cursor.execute('''
                    INSERT OR REPLACE INTO techniques 
                    (id, name, description, tactic, data_source, platforms, detection, mitigation, refs, created_at, modified_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    technique_id, name, description, ', '.join(tactics), json_file.name,
                    platforms, detection.strip(), mitigation.strip(), '\n'.join(references),
                    datetime.now(), datetime.now()
                ))
    
    conn.commit()
    conn.close()
    print("ATT&CK SQLite database created successfully!")

def create_enhanced_mapping():
    """Create enhanced port/service to ATT&CK mapping."""
    enhanced_mapping = {
        "port_techniques": {
            # Web servers
            "80": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
                {"id": "T1595.002", "name": "Vulnerability Scanning: Web Scanning", "tactic": "Reconnaissance"},
                {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"}
            ],
            "443": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
                {"id": "T1571", "name": "Non-Standard Port", "tactic": "Defense Evasion"},
                {"id": "T1048.003", "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over Unencrypted Protocol", "tactic": "Exfiltration"}
            ],
            "8080": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
                {"id": "T1571", "name": "Non-Standard Port", "tactic": "Defense Evasion"},
                {"id": "T1595.002", "name": "Vulnerability Scanning: Web Scanning", "tactic": "Reconnaissance"}
            ],
            # Application servers
            "8080": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
            ],
            # Database servers
            "3306": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}
            ],
            "5432": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
            ],
            # Remote access
            "22": [
                {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}
            ],
            "3389": [
                {"id": "T1021.001", "name": "Remote Services: RDP", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}
            ],
            # File transfer
            "21": [
                {"id": "T1071.002", "name": "Application Layer Protocol: File Transfer Protocols", "tactic": "Command and Control"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"}
            ],
            # Email
            "25": [
                {"id": "T1071.003", "name": "Application Layer Protocol: Mail Protocols", "tactic": "Command and Control"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"}
            ],
            # DNS
            "53": [
                {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
                {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
                {"id": "T1048.003", "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over Unencrypted Protocol", "tactic": "Exfiltration"}
            ]
        },
        "service_techniques": {
            # Enhanced service mappings
            "tomcat": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"}
            ],
            "jboss": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"}
            ],
            "spring-boot": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution"},
                {"id": "T1595.002", "name": "Vulnerability Scanning: Web Scanning", "tactic": "Reconnaissance"}
            ],
            "nginx": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
                {"id": "T1571", "name": "Non-Standard Port", "tactic": "Defense Evasion"}
            ],
            "apache": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
                {"id": "T1595.002", "name": "Vulnerability Scanning: Web Scanning", "tactic": "Reconnaissance"}
            ],
            "redis": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}
            ],
            "mysql": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}
            ],
            "postgresql": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
            ]
        }
    }
    
    with open('enhanced_attack_mapping.json', 'w') as f:
        json.dump(enhanced_mapping, f, indent=2)
    
    print("Enhanced ATT&CK mapping created!")

if __name__ == "__main__":
    print("Building enhanced MITRE ATT&CK database...")
    
    # Download official data
    download_attack_data()
    
    # Create SQLite database
    create_sqlite_db()
    
    # Create enhanced mapping
    create_enhanced_mapping()
    
    print("\n✅ Enhanced ATT&CK database ready!")
    print("Files created:")
    print("  - data/attack.db (SQLite database)")
    print("  - enhanced_attack_mapping.json")
    print("  - attack_data/ (raw JSON files)")
