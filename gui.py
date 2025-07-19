import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import sqlite3
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Optional
import psutil
import json
import subprocess
import socket
import struct
import platform
from collections import defaultdict, Counter
import ipaddress
import re
import os
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NetworkConnection:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    status: str
    process_name: str
    process_pid: int
    timestamp: datetime

@dataclass
class Anomaly:
    source_ip: str
    anomaly_type: str
    severity: str
    confidence: float
    timestamp: datetime
    details: Dict

@dataclass
class FirewallRule:
    rule_id: str
    source_ip: str
    action: str
    protocol: str
    port: int
    created_at: datetime
    expires_at: datetime
    active: bool

class NetworkMonitor:
    """Real network monitoring using system tools and psutil"""
    
    def __init__(self):
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.connection_history = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.connection_rate_tracker = defaultdict(list)
        self.failed_connections = defaultdict(int)
        
    def get_active_connections(self) -> List[NetworkConnection]:
        """Get real active network connections"""
        connections = []
        try:
            # Get network connections using psutil
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:  # Only connections with remote address
                    try:
                        # Get process info
                        process_name = "Unknown"
                        process_pid = 0
                        if conn.pid:
                            try:
                                process = psutil.Process(conn.pid)
                                process_name = process.name()
                                process_pid = conn.pid
                            except:
                                pass
                        
                        connection = NetworkConnection(
                            local_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                            local_port=conn.laddr.port if conn.laddr else 0,
                            remote_ip=conn.raddr.ip,
                            remote_port=conn.raddr.port,
                            protocol="TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                            status=conn.status,
                            process_name=process_name,
                            process_pid=process_pid,
                            timestamp=datetime.now()
                        )
                        connections.append(connection)
                        
                        # Track for anomaly detection
                        self.track_connection_for_anomalies(connection)
                        
                    except Exception as e:
                        logger.debug(f"Error processing connection: {e}")
                        
        except Exception as e:
            logger.error(f"Error getting network connections: {e}")
            
        return connections
    
    def track_connection_for_anomalies(self, conn: NetworkConnection):
        """Track connections for anomaly detection"""
        now = datetime.now()
        remote_ip = conn.remote_ip
        
        # Track port scanning (multiple ports from same IP)
        if conn.status in ['SYN_SENT', 'TIME_WAIT', 'CLOSED']:
            self.port_scan_tracker[remote_ip].add(conn.remote_port)
        
        # Track connection rate
        self.connection_rate_tracker[remote_ip].append(now)
        
        # Clean old entries (keep last 5 minutes)
        cutoff_time = now - timedelta(minutes=5)
        self.connection_rate_tracker[remote_ip] = [
            t for t in self.connection_rate_tracker[remote_ip] if t > cutoff_time
        ]
        
        # Store connection history
        self.connection_history[remote_ip].append({
            'timestamp': now,
            'local_port': conn.local_port,
            'remote_port': conn.remote_port,
            'protocol': conn.protocol,
            'status': conn.status,
            'process': conn.process_name
        })
        
        # Keep only last 100 connections per IP
        if len(self.connection_history[remote_ip]) > 100:
            self.connection_history[remote_ip] = self.connection_history[remote_ip][-100:]
    
    def detect_anomalies(self) -> List[Anomaly]:
        """Detect network anomalies from real traffic"""
        anomalies = []
        now = datetime.now()
        
        # Check for port scanning
        for ip, ports in self.port_scan_tracker.items():
            if len(ports) > 10:  # More than 10 different ports
                anomaly = Anomaly(
                    source_ip=ip,
                    anomaly_type='port_scan',
                    severity='high',
                    confidence=0.9,
                    timestamp=now,
                    details={
                        'ports_scanned': len(ports),
                        'ports_list': list(ports)[:20],  # First 20 ports
                        'detection_method': 'multiple_port_access'
                    }
                )
                anomalies.append(anomaly)
                # Reset tracker after detection
                self.port_scan_tracker[ip] = set()
        
        # Check for high connection rate (potential DDoS)
        for ip, timestamps in self.connection_rate_tracker.items():
            if len(timestamps) > 50:  # More than 50 connections in 5 minutes
                anomaly = Anomaly(
                    source_ip=ip,
                    anomaly_type='high_connection_rate',
                    severity='high',
                    confidence=0.85,
                    timestamp=now,
                    details={
                        'connection_count': len(timestamps),
                        'time_window': '5_minutes',
                        'rate_per_minute': len(timestamps) / 5,
                        'detection_method': 'connection_rate_analysis'
                    }
                )
                anomalies.append(anomaly)
        
        # Check for suspicious processes
        for ip, history in self.connection_history.items():
            recent_connections = [h for h in history if h['timestamp'] > now - timedelta(minutes=10)]
            if len(recent_connections) > 20:
                processes = [h['process'] for h in recent_connections]
                process_counts = Counter(processes)
                
                # Check for unusual process activity
                for process, count in process_counts.items():
                    if count > 15 and process not in ['chrome.exe', 'firefox.exe', 'python.exe', 'java.exe']:
                        anomaly = Anomaly(
                            source_ip=ip,
                            anomaly_type='suspicious_process_activity',
                            severity='medium',
                            confidence=0.7,
                            timestamp=now,
                            details={
                                'process_name': process,
                                'connection_count': count,
                                'time_window': '10_minutes',
                                'detection_method': 'process_behavior_analysis'
                            }
                        )
                        anomalies.append(anomaly)
        
        return anomalies
    
    def get_network_statistics(self) -> Dict:
        """Get real network statistics"""
        try:
            # Get network IO statistics
            net_io = psutil.net_io_counters()
            
            # Get active connections count
            active_connections = len([c for c in psutil.net_connections() if c.raddr])
            
            # Get listening ports
            listening_ports = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    listening_ports.append(conn.laddr.port)
            
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'active_connections': active_connections,
                'listening_ports': sorted(set(listening_ports)),
                'errors_in': net_io.errin,
                'errors_out': net_io.errout,
                'drop_in': net_io.dropin,
                'drop_out': net_io.dropout
            }
        except Exception as e:
            logger.error(f"Error getting network statistics: {e}")
            return {}

class FirewallManager:
    """Real firewall management using system commands"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        
    def apply_rule(self, rule: FirewallRule) -> bool:
        """Apply real firewall rule using system commands"""
        try:
            if self.is_windows:
                return self._apply_windows_rule(rule)
            elif self.is_linux:
                return self._apply_linux_rule(rule)
            else:
                logger.warning("Unsupported operating system for firewall rules")
                return False
        except Exception as e:
            logger.error(f"Error applying firewall rule: {e}")
            return False
    
    def _apply_windows_rule(self, rule: FirewallRule) -> bool:
        """Apply Windows firewall rule using netsh"""
        try:
            # Create Windows Firewall rule
            rule_name = f"AutoGen_{rule.rule_id}"
            
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                f'action={rule.action.lower()}',
                f'protocol={rule.protocol.lower()}',
                f'remoteip={rule.source_ip}'
            ]
            
            if rule.port > 0:
                cmd.append(f'localport={rule.port}')
            
            # Execute command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Store in database
            self._store_rule_in_db(rule)
            
            logger.info(f"Applied Windows firewall rule: {rule_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply Windows firewall rule: {e}")
            return False
    
    def _apply_linux_rule(self, rule: FirewallRule) -> bool:
        """Apply Linux firewall rule using iptables"""
        try:
            # Create iptables rule
            action = "DROP" if rule.action == "DROP" else "ACCEPT"
            
            cmd = [
                'sudo', 'iptables', '-A', 'INPUT',
                '-s', rule.source_ip,
                '-p', rule.protocol.lower(),
                '-j', action
            ]
            
            if rule.port > 0:
                cmd.extend(['--dport', str(rule.port)])
            
            # Execute command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Store in database
            self._store_rule_in_db(rule)
            
            logger.info(f"Applied Linux iptables rule for {rule.source_ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply Linux firewall rule: {e}")
            return False
    
    def _store_rule_in_db(self, rule: FirewallRule):
        """Store firewall rule in database"""
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO firewall_rules 
            (rule_id, source_ip, action, protocol, port, created_at, expires_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (rule.rule_id, rule.source_ip, rule.action, rule.protocol, 
              rule.port, rule.created_at, rule.expires_at, rule.active))
        conn.commit()
        conn.close()
    
    def remove_expired_rules(self):
        """Remove expired firewall rules"""
        try:
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Get expired rules
            cursor.execute('SELECT * FROM firewall_rules WHERE expires_at < ? AND active = 1', 
                          (datetime.now(),))
            expired_rules = cursor.fetchall()
            
            for rule in expired_rules:
                rule_id = rule[1]  # rule_id column
                source_ip = rule[2]  # source_ip column
                
                # Remove from system firewall
                if self.is_windows:
                    self._remove_windows_rule(f"AutoGen_{rule_id}")
                elif self.is_linux:
                    self._remove_linux_rule(source_ip, rule[4], rule[5])  # protocol, port
                
                # Mark as inactive in database
                cursor.execute('UPDATE firewall_rules SET active = 0 WHERE rule_id = ?', (rule_id,))
            
            conn.commit()
            conn.close()
            
            if expired_rules:
                logger.info(f"Removed {len(expired_rules)} expired firewall rules")
                
        except Exception as e:
            logger.error(f"Error removing expired rules: {e}")
    
    def _remove_windows_rule(self, rule_name: str):
        """Remove Windows firewall rule"""
        try:
            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except Exception as e:
            logger.error(f"Error removing Windows rule {rule_name}: {e}")
    
    def _remove_linux_rule(self, source_ip: str, protocol: str, port: int):
        """Remove Linux iptables rule"""
        try:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', source_ip, '-p', protocol.lower(), '-j', 'DROP']
            if port > 0:
                cmd.extend(['--dport', str(port)])
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except Exception as e:
            logger.error(f"Error removing Linux rule for {source_ip}: {e}")
    
    def generate_rule_from_anomaly(self, anomaly: Anomaly) -> FirewallRule:
        """Generate firewall rule from detected anomaly"""
        rule_id = f"{anomaly.anomaly_type}_{int(time.time())}_{anomaly.source_ip.replace('.', '_')}"
        
        # Determine expiration based on severity
        if anomaly.severity == 'critical':
            expires_at = datetime.now() + timedelta(hours=24)
        elif anomaly.severity == 'high':
            expires_at = datetime.now() + timedelta(hours=6)
        elif anomaly.severity == 'medium':
            expires_at = datetime.now() + timedelta(hours=2)
        else:
            expires_at = datetime.now() + timedelta(hours=1)
        
        # Determine protocol and port from anomaly details
        protocol = "TCP"
        port = 0
        
        if 'target_port' in anomaly.details:
            port = anomaly.details['target_port']
        elif 'ports_list' in anomaly.details and anomaly.details['ports_list']:
            port = anomaly.details['ports_list'][0]  # Block first detected port
        
        return FirewallRule(
            rule_id=rule_id,
            source_ip=anomaly.source_ip,
            action='DROP',
            protocol=protocol,
            port=port,
            created_at=datetime.now(),
            expires_at=expires_at,
            active=True
        )

class DatabaseManager:
    def __init__(self, db_path: str = "firewall_real.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Network connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                local_ip TEXT NOT NULL,
                local_port INTEGER,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER,
                protocol TEXT,
                status TEXT,
                process_name TEXT,
                process_pid INTEGER,
                timestamp DATETIME
            )
        ''')
        
        # Anomalies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                timestamp DATETIME,
                details TEXT
            )
        ''')
        
        # Firewall rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE NOT NULL,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                protocol TEXT,
                port INTEGER,
                created_at DATETIME,
                expires_at DATETIME,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                timestamp DATETIME
            )
        ''')
        
        # Network statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bytes_sent INTEGER,
                bytes_recv INTEGER,
                packets_sent INTEGER,
                packets_recv INTEGER,
                active_connections INTEGER,
                errors_in INTEGER,
                errors_out INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_connection(self, conn: NetworkConnection):
        """Log network connection"""
        db_conn = sqlite3.connect(self.db_path)
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT INTO network_connections 
            (local_ip, local_port, remote_ip, remote_port, protocol, status, process_name, process_pid, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port, 
              conn.protocol, conn.status, conn.process_name, conn.process_pid, conn.timestamp))
        db_conn.commit()
        db_conn.close()
    
    def log_anomaly(self, anomaly: Anomaly):
        """Log anomaly data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO anomalies (source_ip, anomaly_type, severity, confidence, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (anomaly.source_ip, anomaly.anomaly_type, anomaly.severity, 
              anomaly.confidence, anomaly.timestamp, json.dumps(anomaly.details)))
        conn.commit()
        conn.close()
    
    def log_alert(self, level: str, category: str, message: str, source: str = "system"):
        """Log alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (level, category, message, source, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (level, category, message, source, datetime.now()))
        conn.commit()
        conn.close()
    
    def get_active_rules(self) -> List[Dict]:
        """Get active firewall rules"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM firewall_rules WHERE active = 1')
        rules = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        conn.close()
        return rules
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
        alerts = [dict(zip([col[0] for col in cursor.description], row)) for row in cursor.fetchall()]
        conn.close()
        return alerts
    
    def get_network_stats(self) -> Dict:
        """Get network statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent connections count
        cursor.execute('''
            SELECT COUNT(*) FROM network_connections 
            WHERE timestamp > datetime('now', '-1 hour')
        ''')
        connections_last_hour = cursor.fetchone()[0]
        
        # Get top remote IPs
        cursor.execute('''
            SELECT remote_ip, COUNT(*) as count FROM network_connections 
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY remote_ip 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_remote_ips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get top processes
        cursor.execute('''
            SELECT process_name, COUNT(*) as count FROM network_connections 
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY process_name 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        top_processes = [{'process': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        return {
            'connections_last_hour': connections_last_hour,
            'top_remote_ips': top_remote_ips,
            'top_processes': top_processes
        }
    
    def cleanup_old_data(self, days_to_keep: int = 7):
        """Clean up old data to prevent database bloat"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        # Clean old connections
        cursor.execute('DELETE FROM network_connections WHERE timestamp < ?', (cutoff_date,))
        
        # Clean old alerts
        cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff_date,))
        
        # Clean old network stats
        cursor.execute('DELETE FROM network_stats WHERE timestamp < ?', (cutoff_date,))
        
        conn.commit()
        conn.close()

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Network Security Monitor")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0a')
        
        # Initialize components
        self.db_manager = DatabaseManager()
        self.firewall_manager = FirewallManager(self.db_manager)
        self.network_monitor = NetworkMonitor()
        
        # Control variables
        self.monitoring_active = tk.BooleanVar(value=False)
        
        # Threads
        self.monitoring_thread = None
        
        # Create GUI
        self.create_gui()
        
        # Start periodic updates
        self.start_periodic_updates()
        
        # Log startup
        self.db_manager.log_alert('info', 'system', 'Real-Time Network Security Monitor started', 'gui')
    
    def create_gui(self):
        """Create the main GUI interface"""
        # Main container
        main_frame = tk.Frame(self.root, bg='#0a0a0a')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_frame = tk.Frame(main_frame, bg='#0a0a0a', height=80)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, text="🛡️ REAL-TIME NETWORK SECURITY MONITOR", 
                              bg='#0a0a0a', fg='#00ff88', font=('Arial', 22, 'bold'))
        title_label.pack(expand=True)
        
        subtitle_label = tk.Label(title_frame, text="Live Network Traffic Analysis & Automated Threat Response", 
                                 bg='#0a0a0a', fg='#888888', font=('Arial', 12))
        subtitle_label.pack()
        
        # Create notebook for tabs
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#0a0a0a', borderwidth=0)
        style.configure('TNotebook.Tab', background='#1a1a2e', foreground='#ffffff', 
                       padding=[20, 10], font=('Arial', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#16213e')])
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_dashboard_tab(notebook)
        self.create_monitoring_tab(notebook)
        self.create_connections_tab(notebook)
        self.create_rules_tab(notebook)
        self.create_alerts_tab(notebook)
    
    def create_dashboard_tab(self, notebook):
        """Create dashboard tab"""
        dashboard_frame = tk.Frame(notebook, bg='#0a0a0a')
        notebook.add(dashboard_frame, text='📊 Dashboard')
        
        # Status cards
        cards_frame = tk.Frame(dashboard_frame, bg='#0a0a0a')
        cards_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Monitoring status
        monitoring_card = self.create_status_card(cards_frame, "🔍 Monitoring", '#1a1a2e')
        monitoring_card.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.monitoring_status_label = tk.Label(monitoring_card, text="Status: Inactive", 
                                              bg='#1a1a2e', fg='#ff4757', font=('Arial', 12, 'bold'))
        self.monitoring_status_label.pack(pady=5)
        
        # Active connections
        connections_card = self.create_status_card(cards_frame, "🌐 Connections", '#1a1a2e')
        connections_card.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.connections_count_label = tk.Label(connections_card, text="Active: 0", 
                                              bg='#1a1a2e', fg='#00d4aa', font=('Arial', 12, 'bold'))
        self.connections_count_label.pack(pady=5)
        
        # Blocked IPs
        blocked_card = self.create_status_card(cards_frame, "🚫 Blocked IPs", '#1a1a2e')
        blocked_card.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.blocked_count_label = tk.Label(blocked_card, text="Count: 0", 
                                          bg='#1a1a2e', fg='#ff4757', font=('Arial', 12, 'bold'))
        self.blocked_count_label.pack(pady=5)
        
        # Alerts
        alerts_card = self.create_status_card(cards_frame, "⚠️ Alerts", '#1a1a2e')
        alerts_card.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        self.alerts_count_label = tk.Label(alerts_card, text="Recent: 0", 
                                         bg='#1a1a2e', fg='#ffa502', font=('Arial', 12, 'bold'))
        self.alerts_count_label.pack(pady=5)
        
        # Network statistics
        stats_frame = tk.LabelFrame(dashboard_frame, text="Network Statistics", 
                                  bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        stats_grid = tk.Frame(stats_frame, bg='#1a1a2e')
        stats_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Network stats labels
        self.bytes_sent_label = tk.Label(stats_grid, text="Bytes Sent: 0", 
                                       bg='#1a1a2e', fg='#00d4aa', font=('Arial', 10))
        self.bytes_sent_label.grid(row=0, column=0, padx=10, pady=5, sticky='w')
        
        self.bytes_recv_label = tk.Label(stats_grid, text="Bytes Received: 0", 
                                       bg='#1a1a2e', fg='#00d4aa', font=('Arial', 10))
        self.bytes_recv_label.grid(row=0, column=1, padx=10, pady=5, sticky='w')
        
        self.packets_sent_label = tk.Label(stats_grid, text="Packets Sent: 0", 
                                         bg='#1a1a2e', fg='#00d4aa', font=('Arial', 10))
        self.packets_sent_label.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        
        self.packets_recv_label = tk.Label(stats_grid, text="Packets Received: 0", 
                                         bg='#1a1a2e', fg='#00d4aa', font=('Arial', 10))
        self.packets_recv_label.grid(row=1, column=1, padx=10, pady=5, sticky='w')
        
        # System logs
        logs_frame = tk.LabelFrame(dashboard_frame, text="System Logs", 
                                 bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, bg='#0f0f23', fg='#00d4aa', 
                                                 font=('Courier', 9), wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_monitoring_tab(self, notebook):
        """Create monitoring control tab"""
        monitoring_frame = tk.Frame(notebook, bg='#0a0a0a')
        notebook.add(monitoring_frame, text='👁️ Monitoring')
        
        # Control panel
        control_frame = tk.LabelFrame(monitoring_frame, text="Monitoring Controls", 
                                    bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        buttons_frame = tk.Frame(control_frame, bg='#1a1a2e')
        buttons_frame.pack(pady=15)
        
        # Start monitoring
        self.start_monitoring_btn = tk.Button(buttons_frame, text="🚀 Start Real-Time Monitoring", 
                                            command=self.start_monitoring,
                                            bg='#00d4aa', fg='#ffffff', font=('Arial', 12, 'bold'),
                                            relief=tk.FLAT, padx=25, pady=10)
        self.start_monitoring_btn.pack(side=tk.LEFT, padx=10)
        
        ## Stop monitoring
        self.stop_monitoring_btn = tk.Button(buttons_frame, text="⏹️ Stop Monitoring", 
                                           command=self.stop_monitoring,
                                           bg='#ff4757', fg='#ffffff', font=('Arial', 12, 'bold'),
                                           relief=tk.FLAT, padx=25, pady=10, state=tk.DISABLED)
        self.stop_monitoring_btn.pack(side=tk.LEFT, padx=10)
        
        # Settings frame
        settings_frame = tk.LabelFrame(monitoring_frame, text="Monitoring Settings", 
                                     bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        settings_frame.pack(fill=tk.X, padx=10, pady=10)
        
        settings_grid = tk.Frame(settings_frame, bg='#1a1a2e')
        settings_grid.pack(pady=10)
        
        # Scan interval
        tk.Label(settings_grid, text="Scan Interval (seconds):", 
                bg='#1a1a2e', fg='#ffffff', font=('Arial', 10)).grid(row=0, column=0, padx=10, pady=5, sticky='w')
        self.scan_interval_var = tk.StringVar(value="5")
        scan_interval_entry = tk.Entry(settings_grid, textvariable=self.scan_interval_var, 
                                     bg='#0f0f23', fg='#00d4aa', font=('Arial', 10), width=10)
        scan_interval_entry.grid(row=0, column=1, padx=10, pady=5, sticky='w')
        
        # Auto-block threshold
        tk.Label(settings_grid, text="Auto-block Port Scan Threshold:", 
                bg='#1a1a2e', fg='#ffffff', font=('Arial', 10)).grid(row=1, column=0, padx=10, pady=5, sticky='w')
        self.port_scan_threshold_var = tk.StringVar(value="10")
        threshold_entry = tk.Entry(settings_grid, textvariable=self.port_scan_threshold_var, 
                                 bg='#0f0f23', fg='#00d4aa', font=('Arial', 10), width=10)
        threshold_entry.grid(row=1, column=1, padx=10, pady=5, sticky='w')
        
        # Enable auto-blocking
        self.auto_block_var = tk.BooleanVar(value=True)
        auto_block_check = tk.Checkbutton(settings_grid, text="Enable Automatic Blocking", 
                                        variable=self.auto_block_var,
                                        bg='#1a1a2e', fg='#ffffff', font=('Arial', 10),
                                        selectcolor='#0f0f23', activebackground='#1a1a2e')
        auto_block_check.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky='w')
        
        # Real-time activity monitor
        activity_frame = tk.LabelFrame(monitoring_frame, text="Real-Time Activity", 
                                     bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame, bg='#0f0f23', fg='#00d4aa', 
                                                     font=('Courier', 9), wrap=tk.WORD)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_connections_tab(self, notebook):
        """Create active connections tab"""
        connections_frame = tk.Frame(notebook, bg='#0a0a0a')
        notebook.add(connections_frame, text='🌐 Connections')
        
        # Connections table
        connections_table_frame = tk.LabelFrame(connections_frame, text="Active Network Connections", 
                                              bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        connections_table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview for connections
        columns = ('Local IP', 'Local Port', 'Remote IP', 'Remote Port', 'Protocol', 'Status', 'Process', 'PID')
        self.connections_tree = ttk.Treeview(connections_table_frame, columns=columns, show='headings', height=15)
        
        # Configure column headings
        for col in columns:
            self.connections_tree.heading(col, text=col)
            self.connections_tree.column(col, width=100)
        
        # Configure treeview style
        style = ttk.Style()
        style.configure("Treeview", background="#0f0f23", foreground="#00d4aa", 
                       font=('Arial', 9), rowheight=25)
        style.configure("Treeview.Heading", background="#1a1a2e", foreground="#ffffff", 
                       font=('Arial', 10, 'bold'))
        
        # Add scrollbar
        connections_scrollbar = ttk.Scrollbar(connections_table_frame, orient=tk.VERTICAL, 
                                            command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=connections_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        connections_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Refresh button
        refresh_frame = tk.Frame(connections_frame, bg='#0a0a0a')
        refresh_frame.pack(fill=tk.X, padx=10, pady=5)
        
        refresh_btn = tk.Button(refresh_frame, text="🔄 Refresh Connections", 
                              command=self.refresh_connections,
                              bg='#00d4aa', fg='#ffffff', font=('Arial', 10, 'bold'),
                              relief=tk.FLAT, padx=20, pady=5)
        refresh_btn.pack(side=tk.LEFT)
        
        # Connection count label
        self.connection_count_label = tk.Label(refresh_frame, text="Total Connections: 0", 
                                             bg='#0a0a0a', fg='#00d4aa', font=('Arial', 10))
        self.connection_count_label.pack(side=tk.RIGHT)
    
    def create_rules_tab(self, notebook):
        """Create firewall rules tab"""
        rules_frame = tk.Frame(notebook, bg='#0a0a0a')
        notebook.add(rules_frame, text='🛡️ Rules')
        
        # Active rules table
        rules_table_frame = tk.LabelFrame(rules_frame, text="Active Firewall Rules", 
                                        bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        rules_table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview for rules
        rule_columns = ('Rule ID', 'Source IP', 'Action', 'Protocol', 'Port', 'Created', 'Expires')
        self.rules_tree = ttk.Treeview(rules_table_frame, columns=rule_columns, show='headings', height=10)
        
        # Configure column headings
        for col in rule_columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=120)
        
        # Add scrollbar
        rules_scrollbar = ttk.Scrollbar(rules_table_frame, orient=tk.VERTICAL, 
                                      command=self.rules_tree.yview)
        self.rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        rules_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Manual rule creation
        manual_rule_frame = tk.LabelFrame(rules_frame, text="Create Manual Rule", 
                                        bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        manual_rule_frame.pack(fill=tk.X, padx=10, pady=10)
        
        manual_grid = tk.Frame(manual_rule_frame, bg='#1a1a2e')
        manual_grid.pack(pady=10)
        
        # IP address entry
        tk.Label(manual_grid, text="IP Address:", 
                bg='#1a1a2e', fg='#ffffff', font=('Arial', 10)).grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.manual_ip_var = tk.StringVar()
        manual_ip_entry = tk.Entry(manual_grid, textvariable=self.manual_ip_var, 
                                 bg='#0f0f23', fg='#00d4aa', font=('Arial', 10), width=15)
        manual_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Action selection
        tk.Label(manual_grid, text="Action:", 
                bg='#1a1a2e', fg='#ffffff', font=('Arial', 10)).grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.manual_action_var = tk.StringVar(value="DROP")
        action_combo = ttk.Combobox(manual_grid, textvariable=self.manual_action_var, 
                                  values=['DROP', 'ACCEPT'], state='readonly', width=10)
        action_combo.grid(row=0, column=3, padx=5, pady=5)
        
        # Duration selection
        tk.Label(manual_grid, text="Duration:", 
                bg='#1a1a2e', fg='#ffffff', font=('Arial', 10)).grid(row=0, column=4, padx=5, pady=5, sticky='w')
        self.manual_duration_var = tk.StringVar(value="1 hour")
        duration_combo = ttk.Combobox(manual_grid, textvariable=self.manual_duration_var, 
                                    values=['1 hour', '6 hours', '24 hours', '1 week'], 
                                    state='readonly', width=10)
        duration_combo.grid(row=0, column=5, padx=5, pady=5)
        
        # Create rule button
        create_rule_btn = tk.Button(manual_grid, text="Create Rule", 
                                  command=self.create_manual_rule,
                                  bg='#00d4aa', fg='#ffffff', font=('Arial', 10, 'bold'),
                                  relief=tk.FLAT, padx=15, pady=5)
        create_rule_btn.grid(row=0, column=6, padx=10, pady=5)
        
        # Rule management buttons
        rule_buttons_frame = tk.Frame(rules_frame, bg='#0a0a0a')
        rule_buttons_frame.pack(fill=tk.X, padx=10, pady=5)
        
        refresh_rules_btn = tk.Button(rule_buttons_frame, text="🔄 Refresh Rules", 
                                    command=self.refresh_rules,
                                    bg='#00d4aa', fg='#ffffff', font=('Arial', 10, 'bold'),
                                    relief=tk.FLAT, padx=20, pady=5)
        refresh_rules_btn.pack(side=tk.LEFT, padx=5)
        
        delete_rule_btn = tk.Button(rule_buttons_frame, text="🗑️ Delete Selected", 
                                  command=self.delete_selected_rule,
                                  bg='#ff4757', fg='#ffffff', font=('Arial', 10, 'bold'),
                                  relief=tk.FLAT, padx=20, pady=5)
        delete_rule_btn.pack(side=tk.LEFT, padx=5)
    
    def create_alerts_tab(self, notebook):
        """Create alerts tab"""
        alerts_frame = tk.Frame(notebook, bg='#0a0a0a')
        notebook.add(alerts_frame, text='⚠️ Alerts')
        
        # Alerts table
        alerts_table_frame = tk.LabelFrame(alerts_frame, text="Security Alerts", 
                                         bg='#1a1a2e', fg='#ffffff', font=('Arial', 12, 'bold'))
        alerts_table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create treeview for alerts
        alert_columns = ('Time', 'Level', 'Category', 'Message', 'Source')
        self.alerts_tree = ttk.Treeview(alerts_table_frame, columns=alert_columns, show='headings', height=15)
        
        # Configure column headings
        for col in alert_columns:
            self.alerts_tree.heading(col, text=col)
            if col == 'Message':
                self.alerts_tree.column(col, width=400)
            else:
                self.alerts_tree.column(col, width=120)
        
        # Add scrollbar
        alerts_scrollbar = ttk.Scrollbar(alerts_table_frame, orient=tk.VERTICAL, 
                                       command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        alerts_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Alert controls
        alert_controls_frame = tk.Frame(alerts_frame, bg='#0a0a0a')
        alert_controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        refresh_alerts_btn = tk.Button(alert_controls_frame, text="🔄 Refresh Alerts", 
                                     command=self.refresh_alerts,
                                     bg='#00d4aa', fg='#ffffff', font=('Arial', 10, 'bold'),
                                     relief=tk.FLAT, padx=20, pady=5)
        refresh_alerts_btn.pack(side=tk.LEFT, padx=5)
        
        clear_alerts_btn = tk.Button(alert_controls_frame, text="🗑️ Clear All", 
                                   command=self.clear_alerts,
                                   bg='#ff4757', fg='#ffffff', font=('Arial', 10, 'bold'),
                                   relief=tk.FLAT, padx=20, pady=5)
        clear_alerts_btn.pack(side=tk.LEFT, padx=5)
    
    def create_status_card(self, parent, title, bg_color):
        """Create a status card widget"""
        card = tk.Frame(parent, bg=bg_color, relief=tk.RAISED, bd=2)
        title_label = tk.Label(card, text=title, bg=bg_color, fg='#ffffff', 
                              font=('Arial', 14, 'bold'))
        title_label.pack(pady=10)
        return card
    
    def start_monitoring(self):
        """Start real-time network monitoring"""
        if not self.monitoring_active.get():
            self.monitoring_active.set(True)
            self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            
            # Update UI
            self.start_monitoring_btn.config(state=tk.DISABLED)
            self.stop_monitoring_btn.config(state=tk.NORMAL)
            self.monitoring_status_label.config(text="Status: Active", fg='#00d4aa')
            
            # Log event
            self.log_to_activity("🚀 Real-time monitoring started")
            self.db_manager.log_alert('info', 'monitoring', 'Real-time monitoring started', 'gui')
    
    def stop_monitoring(self):
        """Stop real-time network monitoring"""
        if self.monitoring_active.get():
            self.monitoring_active.set(False)
            
            # Update UI
            self.start_monitoring_btn.config(state=tk.NORMAL)
            self.stop_monitoring_btn.config(state=tk.DISABLED)
            self.monitoring_status_label.config(text="Status: Inactive", fg='#ff4757')
            
            # Log event
            self.log_to_activity("⏹️ Real-time monitoring stopped")
            self.db_manager.log_alert('info', 'monitoring', 'Real-time monitoring stopped', 'gui')
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active.get():
            try:
                # Get scan interval
                scan_interval = int(self.scan_interval_var.get())
                
                # Get active connections
                connections = self.network_monitor.get_active_connections()
                
                # Log new connections
                for conn in connections:
                    self.db_manager.log_connection(conn)
                
                # Detect anomalies
                anomalies = self.network_monitor.detect_anomalies()
                
                # Process anomalies
                for anomaly in anomalies:
                    self.db_manager.log_anomaly(anomaly)
                    self.handle_anomaly(anomaly)
                
                # Update UI in main thread
                self.root.after(0, self.update_monitoring_ui, connections, anomalies)
                
                # Remove expired rules
                self.firewall_manager.remove_expired_rules()
                
                # Sleep for specified interval
                time.sleep(scan_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                self.log_to_activity(f"❌ Monitoring error: {e}")
                time.sleep(5)
    
    def handle_anomaly(self, anomaly: Anomaly):
        """Handle detected anomaly"""
        # Log anomaly
        self.log_to_activity(f"🚨 ANOMALY DETECTED: {anomaly.anomaly_type} from {anomaly.source_ip}")
        
        # Create alert
        alert_message = f"Anomaly detected: {anomaly.anomaly_type} from {anomaly.source_ip} (Severity: {anomaly.severity})"
        self.db_manager.log_alert(anomaly.severity, 'anomaly', alert_message, 'monitor')
        
        # Auto-block if enabled
        if self.auto_block_var.get() and anomaly.severity in ['high', 'critical']:
            try:
                # Generate firewall rule
                rule = self.firewall_manager.generate_rule_from_anomaly(anomaly)
                
                # Apply rule
                if self.firewall_manager.apply_rule(rule):
                    self.log_to_activity(f"🛡️ Auto-blocked {anomaly.source_ip} due to {anomaly.anomaly_type}")
                    self.db_manager.log_alert('info', 'firewall', f"Auto-blocked {anomaly.source_ip}", 'auto_block')
                else:
                    self.log_to_activity(f"❌ Failed to block {anomaly.source_ip}")
                    
            except Exception as e:
                logger.error(f"Error auto-blocking {anomaly.source_ip}: {e}")
                self.log_to_activity(f"❌ Auto-block failed for {anomaly.source_ip}: {e}")
    
    def update_monitoring_ui(self, connections, anomalies):
        """Update monitoring UI with new data"""
        # Update connection count
        self.connections_count_label.config(text=f"Active: {len(connections)}")
        
        # Update blocked IPs count
        active_rules = self.db_manager.get_active_rules()
        self.blocked_count_label.config(text=f"Count: {len(active_rules)}")
        
        # Update alerts count
        recent_alerts = self.db_manager.get_recent_alerts(24)
        self.alerts_count_label.config(text=f"Recent: {len(recent_alerts)}")
        
        # Update network statistics
        stats = self.network_monitor.get_network_statistics()
        if stats:
            self.bytes_sent_label.config(text=f"Bytes Sent: {self.format_bytes(stats.get('bytes_sent', 0))}")
            self.bytes_recv_label.config(text=f"Bytes Received: {self.format_bytes(stats.get('bytes_recv', 0))}")
            self.packets_sent_label.config(text=f"Packets Sent: {stats.get('packets_sent', 0):,}")
            self.packets_recv_label.config(text=f"Packets Received: {stats.get('packets_recv', 0):,}")
        
        # Log new anomalies
        for anomaly in anomalies:
            severity_icon = "🔴" if anomaly.severity == 'critical' else "🟠" if anomaly.severity == 'high' else "🟡"
            self.log_to_activity(f"{severity_icon} {anomaly.anomaly_type.upper()}: {anomaly.source_ip} - {anomaly.details}")
    
    def log_to_activity(self, message):
        """Log message to activity monitor"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        # Add to activity text
        self.activity_text.insert(tk.END, formatted_message)
        self.activity_text.see(tk.END)
        
        # Add to system logs
        self.logs_text.insert(tk.END, formatted_message)
        self.logs_text.see(tk.END)
        
        # Limit text length
        if len(self.activity_text.get(1.0, tk.END).split('\n')) > 1000:
            self.activity_text.delete(1.0, "50.0")
        
        if len(self.logs_text.get(1.0, tk.END).split('\n')) > 1000:
            self.logs_text.delete(1.0, "50.0")
    
    def format_bytes(self, bytes_count):
        """Format bytes count for display"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    def refresh_connections(self):
        """Refresh active connections display"""
        # Clear existing items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        # Get current connections
        connections = self.network_monitor.get_active_connections()
        
        # Add to tree
        for conn in connections:
            self.connections_tree.insert('', tk.END, values=(
                conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port,
                conn.protocol, conn.status, conn.process_name, conn.process_pid
            ))
        
        # Update count
        self.connection_count_label.config(text=f"Total Connections: {len(connections)}")
    
    def refresh_rules(self):
        """Refresh firewall rules display"""
        # Clear existing items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        # Get active rules
        rules = self.db_manager.get_active_rules()
        
        # Add to tree
        for rule in rules:
            self.rules_tree.insert('', tk.END, values=(
                rule['rule_id'], rule['source_ip'], rule['action'], rule['protocol'],
                rule['port'], rule['created_at'], rule['expires_at']
            ))
    
    def refresh_alerts(self):
        """Refresh alerts display"""
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Get recent alerts
        alerts = self.db_manager.get_recent_alerts(100)
        
        # Add to tree
        for alert in alerts:
            self.alerts_tree.insert('', tk.END, values=(
                alert['timestamp'], alert['level'], alert['category'], 
                alert['message'], alert['source']
            ))
    
    def create_manual_rule(self):
        """Create manual firewall rule"""
        try:
            ip = self.manual_ip_var.get().strip()
            action = self.manual_action_var.get()
            duration_str = self.manual_duration_var.get()
            
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
            
            # Validate IP address
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                messagebox.showerror("Error", "Invalid IP address format")
                return
            
            # Calculate expiration
            duration_map = {
                '1 hour': timedelta(hours=1),
                '6 hours': timedelta(hours=6),
                '24 hours': timedelta(hours=24),
                '1 week': timedelta(weeks=1)
            }
            
            expires_at = datetime.now() + duration_map[duration_str]
            
            # Create rule
            rule = FirewallRule(
                rule_id=f"manual_{int(time.time())}_{ip.replace('.', '_')}",
                source_ip=ip,
                action=action,
                protocol='TCP',
                port=0,
                created_at=datetime.now(),
                expires_at=expires_at,
                active=True
            )
            
            # Apply rule
            if self.firewall_manager.apply_rule(rule):
                messagebox.showinfo("Success", f"Rule created successfully for {ip}")
                self.log_to_activity(f"🛡️ Manual rule created: {action} {ip} for {duration_str}")
                self.refresh_rules()
                
                # Clear form
                self.manual_ip_var.set("")
            else:
                messagebox.showerror("Error", "Failed to create firewall rule")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create rule: {e}")
    
    def delete_selected_rule(self):
        """Delete selected firewall rule"""
        selected_item = self.rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
        
        # Get rule details
        rule_values = self.rules_tree.item(selected_item[0])['values']
        rule_id = rule_values[0]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm", f"Delete rule {rule_id}?"):
            try:
                # Mark rule as inactive in database
                conn = sqlite3.connect(self.db_manager.db_path)
                cursor = conn.cursor()
                cursor.execute('UPDATE firewall_rules SET active = 0 WHERE rule_id = ?', (rule_id,))
                conn.commit()
                conn.close()
                
                self.log_to_activity(f"🗑️ Deleted rule: {rule_id}")
                self.refresh_rules()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete rule: {e}")
    
    def clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Confirm", "Clear all alerts?"):
            try:
                conn = sqlite3.connect(self.db_manager.db_path)
                cursor = conn.cursor()
                cursor.execute('DELETE FROM alerts')
                conn.commit()
                conn.close()
                
                self.log_to_activity("🗑️ All alerts cleared")
                self.refresh_alerts()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear alerts: {e}")
    
    def start_periodic_updates(self):
        """Start periodic UI updates"""
        self.update_dashboard()
        self.root.after(5000, self.start_periodic_updates)  # Update every 5 seconds
    
    def update_dashboard(self):
        """Update dashboard statistics"""
        try:
            # Update network statistics
            stats = self.network_monitor.get_network_statistics()
            if stats:
                self.bytes_sent_label.config(text=f"Bytes Sent: {self.format_bytes(stats.get('bytes_sent', 0))}")
                self.bytes_recv_label.config(text=f"Bytes Received: {self.format_bytes(stats.get('bytes_recv', 0))}")
                self.packets_sent_label.config(text=f"Packets Sent: {stats.get('packets_sent', 0):,}")
                self.packets_recv_label.config(text=f"Packets Received: {stats.get('packets_recv', 0):,}")
            
            # Update counts
            active_rules = self.db_manager.get_active_rules()
            self.blocked_count_label.config(text=f"Count: {len(active_rules)}")
            
            recent_alerts = self.db_manager.get_recent_alerts(24)
            self.alerts_count_label.config(text=f"Recent: {len(recent_alerts)}")
            
            # Clean up old data periodically
            self.db_manager.cleanup_old_data()
            
        except Exception as e:
            logger.error(f"Error updating dashboard: {e}")
    
    def on_closing(self):
        """Handle application closing"""
        if self.monitoring_active.get():
            self.stop_monitoring()
        
        self.db_manager.log_alert('info', 'system', 'Real-Time Network Security Monitor stopped', 'gui')
        self.root.destroy()

def main():
    """Main application entry point"""
    try:
        root = tk.Tk()
        app = FirewallGUI(root)
        
        # Handle window closing
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        
        # Start the application
        # Start periodic updates
        app.start_periodic_updates()
        
        # Start the GUI event loop
        root.mainloop()
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        print(f"Error: {e}")
        if 'root' in locals():
            try:
                root.destroy()
            except:
                pass

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('network_security.log'),
            logging.StreamHandler()
        ]
    )
    
    # Check for required permissions
    if os.name == 'nt':  # Windows
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("Warning: Administrator privileges may be required for full functionality")
        except:
            pass
    else:  # Unix-like systems
        if os.geteuid() != 0:
            print("Warning: Root privileges may be required for full functionality")
    
    # Start the application
    main()

# Additional utility functions that might be needed:

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ['psutil', 'sqlite3', 'tkinter', 'threading', 'ipaddress']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        print("Please install them using: pip install " + ' '.join(missing_packages))
        return False
    
    return True

def create_initial_config():
    """Create initial configuration file if it doesn't exist"""
    config_path = 'config.json'
    if not os.path.exists(config_path):
        default_config = {
            "scan_interval": 5,
            "port_scan_threshold": 10,
            "auto_block_enabled": True,
            "log_level": "INFO",
            "database_path": "network_security.db",
            "max_log_entries": 10000,
            "alert_retention_days": 30
        }
        
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
            print(f"Created default configuration file: {config_path}")
        except Exception as e:
            print(f"Failed to create config file: {e}")

def setup_database():
    """Setup initial database if it doesn't exist"""
    db_path = 'network_security.db'
    if not os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    protocol TEXT,
                    status TEXT,
                    process_name TEXT,
                    process_pid INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE,
                    source_ip TEXT,
                    action TEXT,
                    protocol TEXT,
                    port INTEGER,
                    created_at DATETIME,
                    expires_at DATETIME,
                    active BOOLEAN DEFAULT 1
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    level TEXT,
                    category TEXT,
                    message TEXT,
                    source TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    anomaly_type TEXT,
                    severity TEXT,
                    details TEXT,
                    resolved BOOLEAN DEFAULT 0
                )
            ''')
            
            conn.commit()
            conn.close()
            print(f"Database initialized: {db_path}")
            
        except Exception as e:
            print(f"Failed to setup database: {e}")

# Run setup functions
if __name__ == "__main__":
    print("Starting Real-Time Network Security Monitor...")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        exit(1)
    
    # Create initial configuration
    create_initial_config()
    
    # Setup database
    setup_database()
    
    print("Setup complete. Starting application...")
    print("=" * 50)
