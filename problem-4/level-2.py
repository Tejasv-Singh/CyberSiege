#!/usr/bin/env python3
"""
Universal SSH Brute Force Defender (Level 2)
A cross-platform solution for detecting and preventing SSH brute force attacks.

Features:
- Real-time alert system (Slack, Email)
- Adaptive blocking with cooldown periods
- Distributed attack detection
- Cross-platform support (Linux, macOS, Windows)
"""

import os
import sys
import time
import json
import logging
import socket
import sqlite3
import smtplib
import requests
import platform
import ipaddress
import datetime
import threading
import configparser
from typing import Dict, List, Set, Union, Optional, Tuple, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from dataclasses import dataclass
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor

# Third-party imports
import yaml
import geoip2.database
from geoip2.errors import AddressNotFoundError

# Platform-specific imports
PLATFORM = platform.system().lower()
if PLATFORM == "linux":
    import iptc  # python-iptables
elif PLATFORM == "darwin":  # macOS
    import subprocess
elif PLATFORM == "windows":
    import win32com.client
    import win32security
    import ntsecuritycon


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/ssh_defender_blocks.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ssh_defender")


@dataclass
class LoginAttempt:
    """Data structure for storing login attempt information."""
    ip: str
    username: str
    timestamp: float
    password: Optional[str] = None
    geo_data: Optional[Dict[str, Any]] = None
    

class ConfigManager:
    """Manages configuration loading and access for different platforms."""
    
    def __init__(self):
        """Initialize the configuration manager and load platform-specific config."""
        self.config = {}
        self.platform = PLATFORM
        self.config_path = self._get_config_path()
        self.load_config()
        self.whitelist = self._load_whitelist()
        
    def _get_config_path(self) -> str:
        """Get the platform-specific configuration file path."""
        if self.platform == "linux":
            return "/etc/ssh-defender.yaml"
        elif self.platform == "darwin":  # macOS
            return os.path.expanduser("~/Library/ssh-defender.conf")
        elif self.platform == "windows":
            return r"C:\ssh-defender\config.ini"
        else:
            raise OSError(f"Unsupported platform: {self.platform}")
    
    def load_config(self) -> None:
        """Load configuration from the appropriate file based on platform."""
        try:
            if self.platform in ["linux", "darwin"]:
                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f)
            elif self.platform == "windows":
                config = configparser.ConfigParser()
                config.read(self.config_path)
                # Convert ConfigParser to dict
                self.config = {s: dict(config.items(s)) for s in config.sections()}
            logger.info(f"Configuration loaded from {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def _load_whitelist(self) -> Set[str]:
        """Load whitelisted IPs from the configuration."""
        whitelist = set()
        
        # Extract whitelist from config
        if self.platform in ["linux", "darwin"]:
            whitelist_data = self.config.get("whitelist", [])
        else:  # Windows
            whitelist_section = self.config.get("Whitelist", {})
            whitelist_data = whitelist_section.get("ips", "").split(",")
        
        # Process and validate IPs
        for ip in whitelist_data:
            ip = ip.strip()
            if ip:
                try:
                    # Validate IP
                    ipaddress.ip_address(ip)
                    whitelist.add(ip)
                except ValueError:
                    logger.warning(f"Invalid IP in whitelist: {ip}")
        
        logger.info(f"Loaded {len(whitelist)} whitelisted IPs")
        return whitelist
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        if self.platform in ["linux", "darwin"]:
            return self.config.get(section, {}).get(key, default)
        else:  # Windows
            return self.config.get(section, {}).get(key, default)
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted."""
        return ip in self.whitelist


class AlertManager:
    """Manages real-time alerts via Slack and email."""
    
    def __init__(self, config_manager: ConfigManager):
        """Initialize the alert manager."""
        self.config = config_manager
        
        # Slack configuration
        slack_config = self.config.get("slack", {}) if PLATFORM in ["linux", "darwin"] else self.config.get("Slack", {})
        self.slack_webhook = slack_config.get("webhook_url", "")
        self.slack_enabled = bool(self.slack_webhook)
        
        # Email configuration
        email_config = self.config.get("email", {}) if PLATFORM in ["linux", "darwin"] else self.config.get("Email", {})
        self.email_enabled = email_config.get("enabled", False)
        self.email_from = email_config.get("from", "")
        self.email_to = email_config.get("to", "")
        self.email_smtp_host = email_config.get("smtp_host", "")
        self.email_smtp_port = int(email_config.get("smtp_port", 587))
        self.email_username = email_config.get("username", "")
        self.email_password = email_config.get("password", "")
        self.email_use_tls = email_config.get("use_tls", True)
        
        # GeoIP database
        geoip_path = self.config.get("geoip", {}).get("database_path", "/usr/share/GeoIP/GeoLite2-City.mmdb")
        try:
            self.geoip_reader = geoip2.database.Reader(geoip_path)
            logger.info("GeoIP database loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load GeoIP database: {e}")
            self.geoip_reader = None
    
    def get_geo_data(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data for an IP address."""
        if self.geoip_reader is None:
            return {"error": "GeoIP database not available"}
        
        try:
            response = self.geoip_reader.city(ip)
            return {
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
        except AddressNotFoundError:
            return {"error": "IP address not found in database"}
        except Exception as e:
            logger.error(f"Error retrieving geo data: {e}")
            return {"error": str(e)}
    
    def get_reverse_dns(self, ip: str) -> str:
        """Perform reverse DNS lookup for an IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return "No reverse DNS record found"
        except Exception as e:
            logger.error(f"Error in reverse DNS lookup: {e}")
            return "Error in reverse DNS lookup"
    
    def send_slack_alert(self, attempt: LoginAttempt, alert_type: str = "single") -> bool:
        """Send alert to Slack webhook."""
        if not self.slack_enabled:
            logger.info("Slack alerts disabled, skipping")
            return False
        
        # Get geolocation data if not already present
        geo_data = attempt.geo_data or self.get_geo_data(attempt.ip)
        attempt.geo_data = geo_data
        
        # Prepare message
        if alert_type == "single":
            title = f"🚨 SSH Brute Force Attempt Detected from {attempt.ip}"
        else:  # distributed
            title = f"🚨 Distributed SSH Brute Force Attack Detected"
            
        message = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP Address:*\n{attempt.ip}"},
                        {"type": "mrkdwn", "text": f"*Username:*\n{attempt.username}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{datetime.datetime.fromtimestamp(attempt.timestamp).strftime('%Y-%m-%d %H:%M:%S')}"},
                    ]
                }
            ]
        }
        
        # Add geolocation info if available
        if "error" not in geo_data:
            geo_block = {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Location:*\n{geo_data.get('city', 'Unknown')}, {geo_data.get('country_name', 'Unknown')}"},
                    {"type": "mrkdwn", "text": f"*Coordinates:*\n{geo_data.get('latitude', 'Unknown')}, {geo_data.get('longitude', 'Unknown')}"}
                ]
            }
            message["blocks"].append(geo_block)
        
        # Add actions
        message["blocks"].append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Emergency Unblock"},
                    "value": attempt.ip,
                    "action_id": "emergency_unblock"
                }
            ]
        })
        
        # Send alert
        try:
            response = requests.post(
                self.slack_webhook,
                headers={"Content-Type": "application/json"},
                data=json.dumps(message),
                timeout=5
            )
            if response.status_code == 200:
                logger.info(f"Slack alert sent successfully for IP {attempt.ip}")
                return True
            else:
                logger.error(f"Failed to send Slack alert: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
            return False
    
    def send_email_alert(self, attempt: LoginAttempt, alert_type: str = "single") -> bool:
        """Send alert via email using SMTP."""
        if not self.email_enabled:
            logger.info("Email alerts disabled, skipping")
            return False
        
        # Get geolocation data if not already present
        geo_data = attempt.geo_data or self.get_geo_data(attempt.ip)
        attempt.geo_data = geo_data
        
        # Get reverse DNS
        reverse_dns = self.get_reverse_dns(attempt.ip)
        
        # Prepare email
        msg = MIMEMultipart('alternative')
        
        if alert_type == "single":
            msg['Subject'] = f"SSH Brute Force Attempt from {attempt.ip}"
        else:
            msg['Subject'] = f"URGENT: Distributed SSH Brute Force Attack Detected"
            
        msg['From'] = self.email_from
        msg['To'] = self.email_to
        
        # HTML content with severity-based coloring
        severity_color = "#FF4500"  # Red-Orange for high severity
        
        html = f"""
        <html>
          <head></head>
          <body>
            <h2 style="color: {severity_color};">SSH Brute Force Detection Alert</h2>
            <p>A potential SSH brute force attack has been detected:</p>
            
            <table border="1" cellpadding="5" cellspacing="0">
              <tr>
                <th>IP Address</th>
                <td>{attempt.ip} ({reverse_dns})</td>
              </tr>
              <tr>
                <th>Username</th>
                <td>{attempt.username}</td>
              </tr>
              <tr>
                <th>Timestamp</th>
                <td>{datetime.datetime.fromtimestamp(attempt.timestamp).strftime('%Y-%m-%d %H:%M:%S')}</td>
              </tr>
        """
        
        # Add geolocation info if available
        if "error" not in geo_data:
            html += f"""
              <tr>
                <th>Country</th>
                <td>{geo_data.get('country_name', 'Unknown')} ({geo_data.get('country_code', 'Unknown')})</td>
              </tr>
              <tr>
                <th>City</th>
                <td>{geo_data.get('city', 'Unknown')}</td>
              </tr>
              <tr>
                <th>Coordinates</th>
                <td>{geo_data.get('latitude', 'Unknown')}, {geo_data.get('longitude', 'Unknown')}</td>
              </tr>
            """
        
        html += """
            </table>
            
            <p>This IP has been automatically blocked for 24 hours.</p>
            <p>To unblock this IP immediately, use the emergency unblock feature in your SSH Defender control panel.</p>
          </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
        try:
            server = smtplib.SMTP(self.email_smtp_host, self.email_smtp_port)
            if self.email_use_tls:
                server.starttls()
            if self.email_username and self.email_password:
                server.login(self.email_username, self.email_password)
            server.sendmail(self.email_from, self.email_to, msg.as_string())
            server.quit()
            logger.info(f"Email alert sent successfully for IP {attempt.ip}")
            return True
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False
    
    def send_alerts(self, attempt: LoginAttempt, alert_type: str = "single") -> None:
        """Send all configured alerts (Slack, email) in parallel."""
        with ThreadPoolExecutor(max_workers=2) as executor:
            slack_future = executor.submit(self.send_slack_alert, attempt, alert_type)
            email_future = executor.submit(self.send_email_alert, attempt, alert_type)
            
            # Get results (and handle any exceptions)
            try:
                slack_result = slack_future.result()
                email_result = email_future.result()
                logger.info(f"Alert results - Slack: {slack_result}, Email: {email_result}")
            except Exception as e:
                logger.error(f"Error during alert sending: {e}")


class BlockHandler(ABC):
    """Abstract base class for platform-specific blocking implementations."""
    
    @abstractmethod
    def block_ip(self, ip: str, duration: int = 86400) -> bool:
        """Block an IP address for the specified duration in seconds."""
        pass
    
    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Unblock a previously blocked IP address."""
        pass
    
    @abstractmethod
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        pass
    
    @abstractmethod
    def reload_blocks(self) -> None:
        """Reload block list after system restart."""
        pass


class LinuxBlockHandler(BlockHandler):
    """Linux-specific implementation using iptables."""
    
    def __init__(self):
        """Initialize the Linux block handler."""
        self.chain_name = "SSH_DEFENDER"
        self.ensure_chain_exists()
        
    def ensure_chain_exists(self) -> None:
        """Ensure the iptables chain exists."""
        try:
            # Check if the chain already exists
            table = iptc.Table(iptc.Table.FILTER)
            if self.chain_name not in table.chains:
                # Create the chain
                iptc.Chain(table, self.chain_name)
                
                # Add a jump rule from INPUT chain to our chain
                chain = iptc.Chain(table, "INPUT")
                rule = iptc.Rule()
                rule.protocol = "tcp"
                match = iptc.Match(rule, "tcp")
                match.dport = "22"  # SSH port
                rule.add_match(match)
                target = iptc.Target(rule, self.chain_name)
                rule.target = target
                chain.insert_rule(rule)
                
                logger.info(f"Created iptables chain {self.chain_name}")
            else:
                logger.info(f"Iptables chain {self.chain_name} already exists")
        except Exception as e:
            logger.error(f"Error ensuring iptables chain exists: {e}")
    
    def block_ip(self, ip: str, duration: int = 86400) -> bool:
        """Block an IP using iptables."""
        try:
            # Create the rule
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            rule = iptc.Rule()
            rule.src = ip
            target = iptc.Target(rule, "DROP")
            rule.target = target
            chain.append_rule(rule)
            
            # Log block with expiration
            expiration_time = time.time() + duration
            with sqlite3.connect("/var/lib/ssh-defender/blocks.db") as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS blocks (ip TEXT PRIMARY KEY, expiration REAL)"
                )
                cursor.execute(
                    "INSERT OR REPLACE INTO blocks VALUES (?, ?)",
                    (ip, expiration_time)
                )
                conn.commit()
            
            logger.info(f"Blocked IP {ip} for {duration} seconds")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP by removing the iptables rule."""
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            
            # Find and delete the rule
            for rule in chain.rules:
                if rule.src == ip:
                    chain.delete_rule(rule)
            
            # Remove from database
            with sqlite3.connect("/var/lib/ssh-defender/blocks.db") as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocks WHERE ip = ?", (ip,))
                conn.commit()
            
            logger.info(f"Unblocked IP {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            
            for rule in chain.rules:
                if rule.src == ip:
                    return True
            return False
        except Exception as e:
            logger.error(f"Error checking if IP {ip} is blocked: {e}")
            return False
    
    def reload_blocks(self) -> None:
        """Reload blocks from database after system restart."""
        try:
            current_time = time.time()
            with sqlite3.connect("/var/lib/ssh-defender/blocks.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, expiration FROM blocks")
                for ip, expiration in cursor.fetchall():
                    # If the block hasn't expired, reinstate it
                    if expiration > current_time:
                        remaining_time = int(expiration - current_time)
                        # Skip database update as we'll just use the existing record
                        self._block_ip_without_db(ip)
                        logger.info(f"Reloaded block for IP {ip} for {remaining_time} more seconds")
                    else:
                        # Block has expired, remove it from the database
                        cursor.execute("DELETE FROM blocks WHERE ip = ?", (ip,))
                conn.commit()
        except Exception as e:
            logger.error(f"Error reloading blocks: {e}")
    
    def _block_ip_without_db(self, ip: str) -> bool:
        """Block an IP without updating the database (for reload use)."""
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            rule = iptc.Rule()
            rule.src = ip
            target = iptc.Target(rule, "DROP")
            rule.target = target
            chain.append_rule(rule)
            return True
        except Exception as e:
            logger.error(f"Failed to reinstate block for IP {ip}: {e}")
            return False


class WindowsBlockHandler(BlockHandler):
    """Windows-specific implementation using Windows Firewall."""
    
    def __init__(self):
        """Initialize the Windows block handler."""
        self.rule_name_prefix = "SSH_DEFENDER_BLOCK_"
        self.db_path = r"C:\ssh-defender\blocks.db"
        self._ensure_db_exists()
    
    def _ensure_db_exists(self) -> None:
        """Ensure the database file and directory exist."""
        db_dir = os.path.dirname(self.db_path)
        os.makedirs(db_dir, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS blocks (ip TEXT PRIMARY KEY, expiration REAL)"
            )
            conn.commit()
    
    def block_ip(self, ip: str, duration: int = 86400) -> bool:
        """Block an IP using Windows Firewall."""
        try:
            # Create firewall rule using PowerShell
            rule_name = f"{self.rule_name_prefix}{ip.replace('.', '_')}"
            ps_command = (
                f"New-NetFirewallRule -Name '{rule_name}' -DisplayName '{rule_name}' "
                f"-Direction Inbound -Protocol TCP -LocalPort 22 -Action Block "
                f"-RemoteAddress {ip}"
            )
            
            subprocess.run(["powershell", "-Command", ps_command], check=True)
            
            # Store in database for cooldown tracking
            expiration_time = time.time() + duration
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO blocks VALUES (?, ?)",
                    (ip, expiration_time)
                )
                conn.commit()
            
            logger.info(f"Blocked IP {ip} for {duration} seconds")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP by removing the Windows Firewall rule."""
        try:
            rule_name = f"{self.rule_name_prefix}{ip.replace('.', '_')}"
            ps_command = f"Remove-NetFirewallRule -Name '{rule_name}' -ErrorAction SilentlyContinue"
            
            subprocess.run(["powershell", "-Command", ps_command], check=True)
            
            # Remove from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM blocks WHERE ip = ?", (ip,))
                conn.commit()
            
            logger.info(f"Unblocked IP {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked in Windows Firewall."""
        try:
            rule_name = f"{self.rule_name_prefix}{ip.replace('.', '_')}"
            ps_command = f"Get-NetFirewallRule -Name '{rule_name}' -ErrorAction SilentlyContinue"
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=False
            )
            
            return result.returncode == 0 and result.stdout.strip() != ""
        except Exception as e:
            logger.error(f"Error checking if IP {ip} is blocked: {e}")
            return False
    
    def reload_blocks(self) -> None:
        """Reload blocks from database after system restart."""
        try:
            current_time = time.time()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip, expiration FROM blocks")
                for ip, expiration in cursor.fetchall():
                    # Check if rule exists already
                    if not self.is_blocked(ip):
                        # If the block hasn't expired, reinstate it
                        if expiration > current_time:
                            remaining_time = int(expiration - current_time)
                            # Create the rule but don't update DB
                            self._block_ip_without_db(ip)
                            logger.info(f"Reloaded block for IP {ip} for {remaining_time} more seconds")
                        else:
                            # Block has expired, remove it from the database
                            cursor.execute("DELETE FROM blocks WHERE ip = ?", (ip,))
                conn.commit()
        except Exception as e:
            logger.error(f"Error reloading blocks: {e}")
    
    def _block_ip_without_db(self, ip: str) -> bool:
        """Block an IP without updating the database (for reload use)."""
        try:
            rule_name = f"{self.rule_name_prefix}{ip.replace('.', '_')}"
            ps_command = (
                f"New-NetFirewallRule -Name '{rule_name}' -DisplayName '{rule_name}' "
                f"-Direction Inbound -Protocol TCP -LocalPort 22 -Action Block "
                f"-RemoteAddress {ip}"
            )
            
            subprocess.run(["powershell", "-Command", ps_command], check=True)
            return True
        except Exception as e:
            logger.error(f"Failed to reinstate block for IP {ip}: {e}")
            return False


class MacOSBlockHandler(BlockHandler):
    """macOS-specific implementation using pf firewall."""
    
    def __init__(self):
        """Initialize the macOS block handler."""
        self.block_file = "/etc/pf.anchors/ssh-defender"
        self.db_path = "/Library/Application Support/ssh-defender/blocks.db"
        self._ensure_files_exist()
    
    def _ensure_files_exist(self) -> None:
        """Ensure required files and directories exist."""
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Create block file if it doesn't exist
        if not os.path.exists(self.block_file):
            with open(self.block_file, 'w') as f:
                f.write("# SSH Defender Block List\n")
        
        # Ensure anchor is included in pf.conf
        try:
            with open("/etc/pf.conf", 'r') as f:
                pf_conf = f.read()
            
            if f"anchor \"ssh-defender\"" not in pf_conf:
                with open("/etc/pf.conf", 'a') as f:
                    f.write("\n# SSH Defender\nanchor \"ssh-defender\"\nload anchor \"ssh-defender\" from \"/etc/pf.anchors/ssh-defender\"\n")
                
                # Reload pf configuration
                subprocess.run(["pfctl", "-f", "/etc/pf.conf"], check=True)
        except Exception as e:
            logger.error(f"Error setting up pf anchor: {e}")
        
        # Initialize database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS blocks (ip TEXT PRIMARY KEY, expiration REAL)"
            )
            conn.commit()
    
    def block_ip(self, ip: str, duration: int = 86400) -> bool:
        """Block an IP using macOS pf firewall."""
        try:
            # Add to block file
            with open(self.block_file, 'r') as f:
                lines = f.readlines()
            
            # Check if IP is already in the file
            rule = f"block in from {ip} to any port 22\n"
            if rule not in lines:
                lines.append(rule)
                
                with open(self.block_file, 'w') as f:
                    f.writelines(lines)
                
                # Reload pf rules
                subprocess.run(["pfctl", "-f", self.block_file], check=True)
            
            # Store in database for cooldown tracking
            expiration_time = time.time() + duration
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO blocks VALUES (?, ?)",
                    (ip, expiration_time)
                )
                conn.commit()
            
            logger.info(f"Blocked IP {ip} for {duration} seconds")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP by removing it from the pf rules."""
        try:
            # Remove from block file
            with open(self.block_file, 'r') as f:
                lines = f.readlines()
            
            rule = f"block in from {ip} to any port 22\n"
            if rule in lines:
                lines.remove(rule)
                
                with open(self.block_file, 'w') as f:
                    f.writelines(lines)
                
                # Reload pf