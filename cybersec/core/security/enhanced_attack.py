"""
Enhanced MITRE ATT&CK Framework Integration with SQLite Database.
"""
import json
import sqlite3
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ATTACKTechnique:
    """Enhanced ATT&CK Technique representation."""
    id: str
    name: str
    description: str
    tactic: str
    platforms: List[str]
    detection: str
    mitigation: str
    references: List[str]
    data_source: str


class EnhancedATTACKClient:
    """Enhanced ATT&CK client with SQLite database support."""
    
    def __init__(self, db_path: str = "data/attack.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()
    
    def _init_db(self):
        """Initialize database connection."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            logger.info(f"Connected to ATT&CK database: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to ATT&CK database: {e}")
            # Fallback to JSON mapping
            self.conn = None
    
    def get_technique_by_id(self, technique_id: str) -> Optional[ATTACKTechnique]:
        """Get technique by ID from database."""
        if not self.conn:
            return None
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM techniques WHERE id = ?",
                (technique_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return ATTACKTechnique(
                    id=row['id'],
                    name=row['name'],
                    description=row['description'],
                    tactic=row['tactic'],
                    platforms=row['platforms'].split(', ') if row['platforms'] else [],
                    detection=row['detection'] or '',
                    mitigation=row['mitigation'] or '',
                    references=row['references'].split('\n') if row['references'] else [],
                    data_source=row['data_source']
                )
        except Exception as e:
            logger.error(f"Error getting technique {technique_id}: {e}")
        
        return None
    
    def search_techniques(self, query: str, limit: int = 10) -> List[ATTACKTechnique]:
        """Search techniques by name or description."""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT * FROM techniques 
                WHERE name LIKE ? OR description LIKE ?
                ORDER BY name
                LIMIT ?
                """,
                (f"%{query}%", f"%{query}%", limit)
            )
            
            techniques = []
            for row in cursor.fetchall():
                techniques.append(ATTACKTechnique(
                    id=row['id'],
                    name=row['name'],
                    description=row['description'],
                    tactic=row['tactic'],
                    platforms=row['platforms'].split(', ') if row['platforms'] else [],
                    detection=row['detection'] or '',
                    mitigation=row['mitigation'] or '',
                    references=row['references'].split('\n') if row['references'] else [],
                    data_source=row['data_source']
                ))
            
            return techniques
        except Exception as e:
            logger.error(f"Error searching techniques: {e}")
            return []
    
    def get_techniques_by_tactic(self, tactic: str) -> List[ATTACKTechnique]:
        """Get all techniques for a specific tactic."""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT * FROM techniques WHERE tactic LIKE ? ORDER BY name",
                (f"%{tactic}%",)
            )
            
            techniques = []
            for row in cursor.fetchall():
                techniques.append(ATTACKTechnique(
                    id=row['id'],
                    name=row['name'],
                    description=row['description'],
                    tactic=row['tactic'],
                    platforms=row['platforms'].split(', ') if row['platforms'] else [],
                    detection=row['detection'] or '',
                    mitigation=row['mitigation'] or '',
                    references=row['references'].split('\n') if row['references'] else [],
                    data_source=row['data_source']
                ))
            
            return techniques
        except Exception as e:
            logger.error(f"Error getting techniques for tactic {tactic}: {e}")
            return []
    
    def get_all_tactics(self) -> List[str]:
        """Get all unique tactics."""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT DISTINCT tactic FROM techniques WHERE tactic != '' ORDER BY tactic")
            
            tactics = []
            for row in cursor.fetchall():
                tactics.extend(row[0].split(', '))
            
            return sorted(list(set(tactics)))
        except Exception as e:
            logger.error(f"Error getting tactics: {e}")
            return []
    
    def get_related_techniques(self, technique_id: str) -> List[ATTACKTechnique]:
        """Get techniques related to the given technique (same tactic)."""
        technique = self.get_technique_by_id(technique_id)
        if not technique:
            return []
        
        # Get techniques from the same tactics
        related = []
        for tactic in technique.tactic.split(', '):
            related.extend(self.get_techniques_by_tactic(tactic))
        
        # Remove the original technique
        related = [t for t in related if t.id != technique_id]
        
        return related[:10]  # Limit to 10 related techniques
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


class EnhancedATTACKMapping:
    """Enhanced ATT&CK mapping with database support."""
    
    def __init__(self, db_path: str = "data/attack.db"):
        self.client = EnhancedATTACKClient(db_path)
        self.enhanced_mapping = self._load_enhanced_mapping()
    
    def _load_enhanced_mapping(self) -> Dict[str, Any]:
        """Load enhanced mapping from JSON file."""
        try:
            mapping_file = Path("enhanced_attack_mapping.json")
            if mapping_file.exists():
                with open(mapping_file) as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading enhanced mapping: {e}")
        
        # Fallback to basic mapping
        return {
            "port_techniques": {},
            "service_techniques": {}
        }
    
    def get_port_techniques(self, port: int) -> List[Dict[str, Any]]:
        """Get techniques for a port with enhanced data."""
        port_str = str(port)
        
        # Get basic mapping
        basic_techniques = self.enhanced_mapping.get("port_techniques", {}).get(port_str, [])
        
        # Enhance with database data
        enhanced_techniques = []
        for tech in basic_techniques:
            technique_detail = self.client.get_technique_by_id(tech["id"])
            if technique_detail:
                enhanced_tech = {
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "url": tech.get("url", f"https://attack.mitre.org/techniques/{tech['id']}/"),
                    "description": technique_detail.description,
                    "platforms": technique_detail.platforms,
                    "detection": technique_detail.detection,
                    "mitigation": technique_detail.mitigation,
                    "references": technique_detail.references,
                    "source": f"port:{port_str}"
                }
                enhanced_techniques.append(enhanced_tech)
            else:
                # Fallback to basic data
                enhanced_techniques.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "url": tech.get("url", f"https://attack.mitre.org/techniques/{tech['id']}/"),
                    "description": "",
                    "platforms": [],
                    "detection": "",
                    "mitigation": "",
                    "references": [],
                    "source": f"port:{port_str}"
                })
        
        return enhanced_techniques
    
    def get_service_techniques(self, service: str) -> List[Dict[str, Any]]:
        """Get techniques for a service with enhanced data."""
        service_lower = service.lower()
        
        # Get basic mapping
        basic_techniques = self.enhanced_mapping.get("service_techniques", {}).get(service_lower, [])
        
        # Enhance with database data
        enhanced_techniques = []
        for tech in basic_techniques:
            technique_detail = self.client.get_technique_by_id(tech["id"])
            if technique_detail:
                enhanced_tech = {
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "url": tech.get("url", f"https://attack.mitre.org/techniques/{tech['id']}/"),
                    "description": technique_detail.description,
                    "platforms": technique_detail.platforms,
                    "detection": technique_detail.detection,
                    "mitigation": technique_detail.mitigation,
                    "references": technique_detail.references,
                    "source": f"service:{service_lower}"
                }
                enhanced_techniques.append(enhanced_tech)
            else:
                # Fallback to basic data
                enhanced_techniques.append({
                    "id": tech["id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "url": tech.get("url", f"https://attack.mitre.org/techniques/{tech['id']}/"),
                    "description": "",
                    "platforms": [],
                    "detection": "",
                    "mitigation": "",
                    "references": [],
                    "source": f"service:{service_lower}"
                })
        
        return enhanced_techniques
    
    def get_all_techniques_for_scan(self, ports: List[int], services: List[str]) -> Dict[str, Any]:
        """Get all techniques for a scan with full details."""
        all_techniques = []
        tactics_set = set()
        
        # Get port-based techniques
        for port in ports:
            techniques = self.get_port_techniques(port)
            all_techniques.extend(techniques)
            for tech in techniques:
                tactics_set.update(tech["tactic"].split(", "))
        
        # Get service-based techniques
        for service in services:
            techniques = self.get_service_techniques(service)
            all_techniques.extend(techniques)
            for tech in techniques:
                tactics_set.update(tech["tactic"].split(", "))
        
        # Remove duplicates
        unique_techniques = {}
        for tech in all_techniques:
            if tech["id"] not in unique_techniques:
                unique_techniques[tech["id"]] = tech
        
        return {
            "attack_techniques": list(unique_techniques.values()),
            "tactics_summary": sorted(list(tactics_set)),
            "attack_technique_count": len(unique_techniques),
            "total_ports_scanned": len(ports),
            "total_services_detected": len(services)
        }
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific technique."""
        technique = self.client.get_technique_by_id(technique_id)
        if not technique:
            return None
        
        # Get related techniques
        related = self.client.get_related_techniques(technique_id)
        
        return {
            "id": technique.id,
            "name": technique.name,
            "description": technique.description,
            "tactic": technique.tactic,
            "platforms": technique.platforms,
            "detection": technique.detection,
            "mitigation": technique.mitigation,
            "references": technique.references,
            "data_source": technique.data_source,
            "related_techniques": [
                {
                    "id": t.id,
                    "name": t.name,
                    "tactic": t.tactic
                }
                for t in related
            ]
        }
    
    def close(self):
        """Close database connection."""
        self.client.close()


# Usage example
if __name__ == "__main__":
    # Initialize enhanced ATT&CK client
    attack_client = EnhancedATTACKMapping()
    
    # Get techniques for port 8080
    port_8080_techniques = attack_client.get_port_techniques(8080)
    print(f"Port 8080 techniques: {len(port_8080_techniques)}")
    
    # Get techniques for Tomcat service
    tomcat_techniques = attack_client.get_service_techniques("tomcat")
    print(f"Tomcat techniques: {len(tomcat_techniques)}")
    
    # Search for techniques
    search_results = attack_client.client.search_techniques("brute force")
    print(f"Search results: {len(search_results)}")
    
    # Get all tactics
    tactics = attack_client.client.get_all_tactics()
    print(f"Total tactics: {len(tactics)}")
    
    attack_client.close()
