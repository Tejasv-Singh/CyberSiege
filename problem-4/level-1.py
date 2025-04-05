#!/usr/bin/env python3
"""
SSH Brute Force Protection - Linux Implementation
Monitors SSH login attempts and blocks suspicious IPs using iptables/ufw.
"""

import os
import re
import time
import logging
import argparse
import subprocess
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import fcntl
import threading
import signal
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('ssh-brute-force-blocker')


class LogMonitor:
    """Monitors auth.log or journalctl for SSH authentication failures."""
    
    # Regex patterns for log parsing
    LOG_PATTERNS = {
        'file': re.compile(
            r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(Failed password|Invalid user).*for.*from\s+(\d+\.\d+\.\d+\.\d+)'
        ),
        'journalctl': re.compile(
            r'(\d+-\d+-\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(Failed password|Invalid user).*for.*from\s+(\d+\.\d+\.\d+\.\d+)'
        )
    }
    
    # Timestamp formats for different log sources
    TIMESTAMP_FORMATS = {
        'file': '%Y %b %d %H:%M:%S',
        'journalctl': '%Y-%m-%d %H:%M:%S'
    }

    def __init__(self, threat_detector):
        self.threat_detector = threat_detector
        self.log_file_path = '/var/log/auth.log'
        self.running = False
        self.monitoring_thread = None
        self.monitor_methods = {
            'file': self._monitor_auth_log,
            'journalctl': self._monitor_journalctl
        }
        
    def _test_log_access(self) -> str:
        """Test which log source is available and return its type."""
        # Try auth.log first
        try:
            with open(self.log_file_path, 'r'):
                return 'file'
        except (FileNotFoundError, PermissionError):
            pass
        
        # Try journalctl
        try:
            subprocess.run(['journalctl', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return 'journalctl'
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("Could not access auth.log or journalctl. Exiting.")
            sys.exit(1)
    
    def _monitor_auth_log(self):
        """Monitor auth.log file for SSH failures."""
        try:
            with open(self.log_file_path, 'r') as f:
                # Seek to the end of the file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    self._process_line_or_sleep(line, 'file')
        except Exception as e:
            logger.error(f"Error monitoring auth.log: {e}")
            self.running = False
    
    def _monitor_journalctl(self):
        """Monitor SSH logs using journalctl command."""
        try:
            process = subprocess.Popen(
                ['journalctl', '-f', '-u', 'ssh', '-u', 'sshd', '--no-pager'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            while self.running:
                line = process.stdout.readline()
                self._process_line_or_sleep(line, 'journalctl')
                    
            process.terminate()
        except Exception as e:
            logger.error(f"Error monitoring journalctl: {e}")
            self.running = False
    
    def _process_line_or_sleep(self, line: str, source_type: str):
        """Process a log line if present, otherwise sleep."""
        if line:
            self._process_log_line(line, source_type)
        else:
            time.sleep(0.1)
    
    def _parse_timestamp(self, timestamp_str: str, source_type: str) -> Optional[datetime]:
        """Parse timestamp from log entry based on source type."""
        try:
            timestamp_format = self.TIMESTAMP_FORMATS[source_type]
            
            # For auth.log, add current year (not present in log)
            timestamp = (
                datetime.strptime(timestamp_str, timestamp_format)
                if source_type == 'journalctl'
                else datetime.strptime(f"{datetime.now().year} {timestamp_str}", timestamp_format)
            )
            
            # Handle year rollover for auth.log
            rollover_threshold = datetime.now() + timedelta(days=1)
            timestamp = (
                timestamp.replace(year=datetime.now().year - 1)
                if source_type == 'file' and timestamp > rollover_threshold
                else timestamp
            )
            
            return timestamp
        except ValueError:
            logger.warning(f"Could not parse timestamp: {timestamp_str}")
            return None
    
    def _process_log_line(self, line: str, source_type: str):
        """Process a log line and extract relevant information."""
        pattern = self.LOG_PATTERNS[source_type]
        match = pattern.search(line)
        
        if not match:
            return
            
        timestamp_str, failure_type, src_ip = match.groups()
        timestamp = self._parse_timestamp(timestamp_str, source_type)
        
        if timestamp:
            logger.debug(f"Detected login failure from {src_ip}")
            self.threat_detector.register_failure(src_ip, timestamp)
    
    def start(self):
        """Start monitoring logs."""
        if self.running:
            logger.warning("Monitor is already running")
            return
            
        log_source = self._test_log_access()
        self.running = True
        
        logger.info(f"Starting to monitor SSH logs via {log_source}")
        monitor_method = self.monitor_methods[log_source]
        
        self.monitoring_thread = threading.Thread(target=monitor_method)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
    
    def stop(self):
        """Stop monitoring logs."""
        self.running = False
        try:
            self.monitoring_thread and self.monitoring_thread.is_alive() and self.monitoring_thread.join(2)
        except Exception:
            pass
        logger.info("Log monitoring stopped")


class ThreatDetector:
    """Detects potential threats based on failed login attempts."""
    
    def __init__(self, threshold: int, interval: int, whitelist: List[str]):
        self.threshold = threshold
        self.interval = interval  # seconds
        self.whitelist = set(whitelist)
        self.firewall_manager = None  # Set later
        self.failures = defaultdict(list)
        self.blocked_ips = set()
        
    def set_firewall_manager(self, firewall_manager):
        """Set the firewall manager to use for blocking."""
        self.firewall_manager = firewall_manager
        
    def register_failure(self, ip: str, timestamp: datetime):
        """Register a failed login attempt."""
        # Early returns for whitelisted or already blocked IPs
        if ip in self.whitelist or ip in self.blocked_ips:
            logger.debug(f"Ignoring IP: {ip} (whitelisted or already blocked)")
            return
            
        # Add the new failure
        self.failures[ip].append(timestamp)
        
        # Clean up old entries
        cutoff_time = datetime.now() - timedelta(seconds=self.interval)
        self.failures[ip] = [ts for ts in self.failures[ip] if ts > cutoff_time]
        
        # Check threshold and block IP if needed
        failure_count = len(self.failures[ip])
        threshold_exceeded = failure_count >= self.threshold
        
        if threshold_exceeded and self.firewall_manager:
            logger.warning(f"Threshold exceeded for IP {ip}: {failure_count} failures in the last {self.interval} seconds")
            self.firewall_manager.block_ip(ip)
            self.blocked_ips.add(ip)
            self.failures[ip] = []  # Clear the failures for this IP


class FirewallManager:
    """Manages firewall rules to block malicious IPs."""
    
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.firewall_type = self._detect_firewall()
        self.block_methods = {
            'ufw': self._block_with_ufw,
            'iptables': self._block_with_iptables,
            None: self._block_unavailable
        }
        
    def _detect_firewall(self) -> Optional[str]:
        """Detect which firewall system is available."""
        firewall_checks = [
            ('ufw', ['ufw', 'status'], lambda out: 'Status: active' in out),
            ('iptables', ['iptables', '--version'], lambda _: True)
        ]
        
        for fw_type, cmd, check_func in firewall_checks:
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0 and check_func(result.stdout):
                    logger.info(f"Using {fw_type} firewall")
                    return fw_type
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
                
        logger.error("No supported firewall (ufw/iptables) found on the system")
        return None
        
    def _block_with_ufw(self, ip: str) -> bool:
        """Block an IP address using UFW."""
        cmd = ['ufw', 'deny', 'from', ip, 'to', 'any']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    
    def _block_with_iptables(self, ip: str) -> bool:
        """Block an IP address using iptables."""
        # Check if rule already exists
        check_cmd = f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null"
        rule_exists = os.system(check_cmd) == 0
        
        if rule_exists:
            logger.info(f"IP {ip} is already blocked")
            return True
            
        cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    
    def _block_unavailable(self, ip: str) -> bool:
        """Handle case where no firewall is available."""
        logger.error("Cannot block IP - no firewall available")
        return False
        
    def block_ip(self, ip: str) -> bool:
        """Block an IP address using the detected firewall."""
        if self.dry_run:
            logger.info(f"[DRY RUN] Would block IP: {ip}")
            return True
        
        try:
            block_method = self.block_methods[self.firewall_type]
            success = block_method(ip)
            
            logger.info(f"Successfully blocked IP: {ip}" if success else f"Failed to block IP: {ip}")
            return success
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {e}")
            return False


def check_root() -> bool:
    """Check if the script is run with root privileges."""
    has_root = os.geteuid() == 0
    
    if not has_root:
        logger.error("This script must be run with root privileges (sudo)")
        
    return has_root


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='SSH Brute Force Protection')
    parser.add_argument('--threshold', type=int, default=5,
                        help='Number of failed attempts before blocking (default: 5)')
    parser.add_argument('--interval', type=int, default=60,
                        help='Time window in seconds to count failures (default: 60)')
    parser.add_argument('--whitelist', type=str, nargs='+', default=[],
                        help='IPs to never block (e.g., your own IP)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Simulate actions without actually blocking IPs')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        help='Set the logging level')
    return parser.parse_args()


def handle_signals(signum, frame):
    """Handle termination signals to clean up properly."""
    logger.info("Received termination signal. Shutting down...")
    log_monitor.stop()
    sys.exit(0)


if __name__ == "__main__":
    # Parse arguments
    args = parse_arguments()
    
    # Set log level
    logger.setLevel(getattr(logging, args.log_level))
    
    # Exit if not root
    check_root() or sys.exit(1)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, handle_signals)
    signal.signal(signal.SIGTERM, handle_signals)
    
    # Initialize components
    threat_detector = ThreatDetector(
        threshold=args.threshold,
        interval=args.interval,
        whitelist=args.whitelist
    )
    
    firewall_manager = FirewallManager(dry_run=args.dry_run)
    threat_detector.set_firewall_manager(firewall_manager)
    
    log_monitor = LogMonitor(threat_detector)
    
    # Start monitoring
    logger.info(f"Starting SSH brute force protection with threshold={args.threshold} "
                f"and interval={args.interval}s")
    
    args.whitelist and logger.info(f"Whitelisted IPs: {', '.join(args.whitelist)}")
    args.dry_run and logger.info("Running in DRY RUN mode - no IPs will be blocked")
    
    log_monitor.start()
    
    # Keep the main thread running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_monitor.stop()
        logger.info("SSH brute force protection stopped")