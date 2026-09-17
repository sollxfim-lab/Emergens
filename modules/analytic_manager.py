#!/usr/bin/env python3
"""
Analytic Manager – Combines exploit repository, brute force, SQLi, XSS
Oxysintx Framework

Location: modules/analytic_manager.py
"""

import json
import time
import threading
from typing import Dict, List, Optional

from modules.exploit_repository import ExploitRepository
from modules.brute_force import BruteForceAttack
from modules.sql_injection import run_sql_injection
from modules.xss import run_xss

class AnalyticDataManager:
    def __init__(self):
        self.repository = ExploitRepository()
        self.brute_force = BruteForceAttack()
        self._lock = threading.Lock()

    def get_statistics(self) -> Dict:
        all_exploits = self.repository.get_all()
        return {
            'total_exploits': len(all_exploits),
            'by_category': {
                cat.value: len(self.repository.get_by_category(cat))
                for cat in self.repository._by_category
            },
            'by_service': {
                svc: len(self.repository.get_by_service(svc))
                for svc in self.repository._by_service
            },
            'risk_levels': {
                'critical': len([e for e in all_exploits if e.risk_level == 'critical']),
                'high': len([e for e in all_exploits if e.risk_level == 'high']),
                'medium': len([e for e in all_exploits if e.risk_level == 'medium']),
                'low': len([e for e in all_exploits if e.risk_level == 'low']),
            }
        }

    def list_exploits(self, category=None, service=None) -> List[Dict]:
        if category:
            exploits = self.repository.get_by_category(category) if isinstance(category, str) else []
        elif service:
            exploits = self.repository.get_by_service(service)
        else:
            exploits = self.repository.get_all()
        return [e.to_dict() for e in exploits]

    def search_exploits(self, query) -> List[Dict]:
        return [e.to_dict() for e in self.repository.search(query)]

    def run_brute_force(self, target, protocols=None, username_file='data1.txt', password_file='data1.txt'):
        return self.brute_force.run_full_attack(target, protocols, username_file, password_file)

    def stop_brute_force(self):
        self.brute_force.stop()

    def run_sql_injection_scan(self, url, method='GET', params=None):
        return run_sql_injection(url, method, params)

    def run_xss_scan(self, url, method='GET', params=None):
        return run_xss(url, method, params)

    def export_data(self, output_file='analytic_data_export.json'):
        data = {
            'timestamp': time.time(),
            'statistics': self.get_statistics(),
            'exploits': [e.to_dict() for e in self.repository.get_all()],
            'brute_force_results': self.brute_force.results
        }
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        return data