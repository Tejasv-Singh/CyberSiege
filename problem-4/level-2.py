#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Brute Force IP Blocking System

This module provides classes and functions to implement an adaptive IP blocking system
for SSH brute force defense, with cross-platform support.
"""

import os
import sys
import json
import yaml
import logging
import ipaddress
import subprocess
import threading
import time
from datetime import datetime, timedelta
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_blocker')

# Ensure log directory exists
BLOCK_LOG_PATH = '/var/log/ssh_defender_blocks.log'
os.makedirs(os.path.dirname(BLOCK_LOG_PATH), exist_ok=True)

# Configure file handler for block log
block_file_handler = logging.FileHandler(BLOCK_LOG_PATH)
block_file_handler.setLevel(logging.INFO)
block_formatter = logging.Formatter('%(asctime)s - %(message)s')
block_file_handler.setFormatter(block_formatter)

block_logger = logging.getLogger('ssh_block_logger')
block_logger.addHandler(block_file_handler)
block_logger.setLevel(logging.INFO)
block_logger.propagate = False  # Don't propagate to parent loggers

# Block storage paths
BLOCK_STORAGE_DIR = '/var/lib/ssh_defender'
os.makedirs(BLOCK_STORAGE_DIR, exist_ok=True)
BLOCK_STORAGE_PATH = os.path.join(BLOCK_STORAGE_DIR, 'active_blocks.json')

class IPBlocker(ABC):
    """Abstract base class for platform-specific IP blocking implementations."""
    
    @abstractmethod
    def block_ip(self, ip_address, duration_hours=24):
        """
        Block an IP address for the specified duration.
        
        Args:
            ip_address (str): The IP address to block
            duration_hours (int): Number of hours to block the IP for
            
        Returns:
            bool: True if block was successful, False otherwise
        """
        pass
        
    @abstractmethod
    def unblock_ip(self, ip_address):
        """
        Remove a block on an IP address.
        
        Args:
            ip_address (str): The IP address to unblock
            
        Returns:
            bool: True if unblock was successful, False otherwise
        """
        pass
        
    @abstractmethod
    def is_blocked(self, ip_address):
        """
        Check if an IP address is currently blocked.
        
        Args:
            ip_address (str): The IP address to check
            
        Returns:
            bool: True if IP is blocked, False otherwise
        """
        pass
        
    @abstractmethod
    def reload_blocks(self, active_blocks):
        """
        Reload active blocks from saved state (e.g., after reboot).
        
        Args:
            active_blocks (dict): Dictionary of IP addresses and their expiration times
            
        Returns:
            bool: True if reload was successful, False otherwise
        """
        pass


class LinuxIPBlocker(IPBlocker):
    """Linux implementation of IP blocking using iptables."""
    
    def __init__(self):
        """Initialize the Linux IP blocker."""
        try:
            import iptc
            self.iptc = iptc
            self.chain_name = "SSH_DEFENDER"
            self._ensure_chain_exists()
            logger.info("Linux IPBlocker initialized with python-iptables")
        except ImportError:
            logger.error("python-iptables not installed. Please install with: pip install python-iptables")
            sys.exit(1)
    
    def _ensure_chain_exists(self):
        """Ensure the SSH_DEFENDER chain exists and is hooked up to INPUT."""
        # Create chain if it doesn't exist
        table = self.iptc.Table(self.iptc.Table.FILTER)
        try:
            chain = self.iptc.Chain(table, self.chain_name)
        except self.iptc.IPTCError:
            # Chain doesn't exist, create it
            table.create_chain(self.chain_name)
            logger.info(f"Created iptables chain {self.chain_name}")
        
        # Check if jump rule exists in INPUT chain
        input_chain = self.iptc.Chain(table, "INPUT")
        jump_exists = False
        
        for rule in input_chain.rules:
            if rule.target and rule.target.name == self.chain_name:
                jump_exists = True
                break
        
        # Add jump rule if it doesn't exist
        if not jump_exists:
            rule = self.iptc.Rule()
            rule.protocol = "tcp"
            match = rule.create_match("tcp")
            match.dport = "22"
            rule.target = rule.create_target(self.chain_name)
            input_chain.insert_rule(rule)
            logger.info(f"Added jump rule from INPUT to {self.chain_name}")
    
    def block_ip(self, ip_address, duration_hours=24):
        """Block an IP address using iptables."""
        try:
            table = self.iptc.Table(self.iptc.Table.FILTER)
            chain = self.iptc.Chain(table, self.chain_name)
            
            # Check if IP is already blocked
            if self.is_blocked(ip_address):
                logger.info(f"IP {ip_address} is already blocked")
                return True
            
            # Create rule to block the IP
            rule = self.iptc.Rule()
            rule.src = ip_address
            rule.protocol = "tcp"
            match = rule.create_match("tcp")
            match.dport = "22"
            rule.target = rule.create_target("DROP")
            
            # Insert the rule
            chain.insert_rule(rule)
            
            expiry_time = datetime.now() + timedelta(hours=duration_hours)
            block_logger.info(f"BLOCKED: {ip_address} until {expiry_time.isoformat()}")
            logger.info(f"Successfully blocked IP {ip_address} for {duration_hours} hours")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address):
        """Remove a block for an IP address from iptables."""
        try:
            table = self.iptc.Table(self.iptc.Table.FILTER)
            chain = self.iptc.Chain(table, self.chain_name)
            
            # Find and delete the rule for this IP
            for rule in chain.rules:
                if rule.src == ip_address:
                    chain.delete_rule(rule)
                    block_logger.info(f"UNBLOCKED: {ip_address}")
                    logger.info(f"Successfully unblocked IP {ip_address}")
                    return True
            
            logger.info(f"IP {ip_address} was not found in block list")
            return False
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip_address}: {str(e)}")
            return False
    
    def is_blocked(self, ip_address):
        """Check if an IP address is currently blocked in iptables."""
        try:
            table = self.iptc.Table(self.iptc.Table.FILTER)
            chain = self.iptc.Chain(table, self.chain_name)
            
            for rule in chain.rules:
                if rule.src == ip_address:
                    return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to check block status for IP {ip_address}: {str(e)}")
            return False
    
    def reload_blocks(self, active_blocks):
        """Reload active blocks from saved state."""
        try:
            table = self.iptc.Table(self.iptc.Table.FILTER)
            chain = self.iptc.Chain(table, self.chain_name)
            
            # Clear existing rules
            chain.flush()
            
            # Reload active blocks
            count = 0
            for ip, expiry_time in active_blocks.items():
                # Only reload if the block hasn't expired
                if datetime.fromisoformat(expiry_time) > datetime.now():
                    rule = self.iptc.Rule()
                    rule.src = ip
                    rule.protocol = "tcp"
                    match = rule.create_match("tcp")
                    match.dport = "22"
                    rule.target = rule.create_target("DROP")
                    chain.insert_rule(rule)
                    count += 1
            
            logger.info(f"Reloaded {count} active IP blocks")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload IP blocks: {str(e)}")
            return False


class WindowsIPBlocker(IPBlocker):
    """Windows implementation of IP blocking using Windows Firewall."""
    
    def __init__(self):
        """Initialize the Windows IP blocker."""
        self.rule_name_prefix = "SSH_Defender_Block_"
        logger.info("Windows IPBlocker initialized")
    
    def block_ip(self, ip_address, duration_hours=24):
        """Block an IP address using Windows Firewall."""
        try:
            # Check if already blocked
            if self.is_blocked(ip_address):
                logger.info(f"IP {ip_address} is already blocked")
                return True
            
            # Create a unique rule name
            rule_name = f"{self.rule_name_prefix}{ip_address.replace('.', '_')}"
            
            # Create firewall rule using netsh
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}',
                'protocol=TCP',
                'localport=22',
                'enable=yes'
            ]
            
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            expiry_time = datetime.now() + timedelta(hours=duration_hours)
            block_logger.info(f"BLOCKED: {ip_address} until {expiry_time.isoformat()}")
            logger.info(f"Successfully blocked IP {ip_address} for {duration_hours} hours")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address):
        """Remove a block for an IP address from Windows Firewall."""
        try:
            # Create the rule name to delete
            rule_name = f"{self.rule_name_prefix}{ip_address.replace('.', '_')}"
            
            # Delete the firewall rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name="{rule_name}"'
            ]
            
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            if "No rules match the specified criteria" in result.stderr:
                logger.info(f"IP {ip_address} was not found in block list")
                return False
                
            block_logger.info(f"UNBLOCKED: {ip_address}")
            logger.info(f"Successfully unblocked IP {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock IP {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip_address}: {str(e)}")
            return False
    
    def is_blocked(self, ip_address):
        """Check if an IP address is currently blocked in Windows Firewall."""
        try:
            # Create the rule name to check
            rule_name = f"{self.rule_name_prefix}{ip_address.replace('.', '_')}"
            
            # Check if the rule exists
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                f'name="{rule_name}"'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return "No rules match the specified criteria" not in result.stdout
            
        except Exception as e:
            logger.error(f"Failed to check block status for IP {ip_address}: {str(e)}")
            return False
    
    def reload_blocks(self, active_blocks):
        """Reload active blocks from saved state."""
        try:
            # Get all existing rules
            cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Delete all existing SSH Defender rules
            for line in result.stdout.splitlines():
                if line.startswith("Rule Name:") and self.rule_name_prefix in line:
                    rule_name = line.split(":", 1)[1].strip()
                    delete_cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name="{rule_name}"']
                    subprocess.run(delete_cmd, capture_output=True)
            
            # Reload active blocks
            count = 0
            for ip, expiry_time in active_blocks.items():
                # Only reload if the block hasn't expired
                if datetime.fromisoformat(expiry_time) > datetime.now():
                    self.block_ip(ip)
                    count += 1
            
            logger.info(f"Reloaded {count} active IP blocks")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload IP blocks: {str(e)}")
            return False


class MacOSIPBlocker(IPBlocker):
    """macOS implementation of IP blocking using pfctl."""
    
    def __init__(self):
        """Initialize the macOS IP blocker."""
        self.pf_file = "/etc/pf.anchors/ssh_defender"
        self.anchor_name = "ssh_defender"
        
        # Ensure anchor is loaded
        self._ensure_anchor_exists()
        logger.info("macOS IPBlocker initialized")
    
    def _ensure_anchor_exists(self):
        """Ensure the pf anchor exists and is loaded."""
        try:
            # Create anchor file if it doesn't exist
            if not os.path.exists(self.pf_file):
                with open(self.pf_file, 'w') as f:
                    f.write("# SSH Defender Blocks\n")
                
                # Check if anchor is in main config
                with open('/etc/pf.conf', 'r') as f:
                    config = f.read()
                
                if f'anchor "{self.anchor_name}"' not in config:
                    logger.error(f"Anchor {self.anchor_name} is not loaded in /etc/pf.conf")
                    logger.error("Please add 'anchor \"ssh_defender\"' to /etc/pf.conf and run 'sudo pfctl -f /etc/pf.conf'")
            
            # Load the anchor
            subprocess.run(['pfctl', '-a', self.anchor_name, '-f', self.pf_file], check=True, capture_output=True)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to initialize pf anchor: {e.stderr}")
        except Exception as e:
            logger.error(f"Failed to initialize pf anchor: {str(e)}")
    
    def block_ip(self, ip_address, duration_hours=24):
        """Block an IP address using pf."""
        try:
            # Check if already blocked
            if self.is_blocked(ip_address):
                logger.info(f"IP {ip_address} is already blocked")
                return True
            
            # Add block rule to anchor file
            with open(self.pf_file, 'a') as f:
                f.write(f"block return in quick proto tcp from {ip_address} to any port 22\n")
            
            # Reload the anchor
            subprocess.run(['pfctl', '-a', self.anchor_name, '-f', self.pf_file], check=True, capture_output=True)
            
            expiry_time = datetime.now() + timedelta(hours=duration_hours)
            block_logger.info(f"BLOCKED: {ip_address} until {expiry_time.isoformat()}")
            logger.info(f"Successfully blocked IP {ip_address} for {duration_hours} hours")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block IP {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {str(e)}")
            return False
    
    def unblock_ip(self, ip_address):
        """Remove a block for an IP address from pf."""
        try:
            # Read existing rules
            with open(self.pf_file, 'r') as f:
                lines = f.readlines()
            
            # Filter out the rule for this IP
            new_lines = [line for line in lines if ip_address not in line]
            
            # If no changes were made, IP wasn't blocked
            if len(lines) == len(new_lines):
                logger.info(f"IP {ip_address} was not found in block list")
                return False
            
            # Write back the file without the rule
            with open(self.pf_file, 'w') as f:
                f.writelines(new_lines)
            
            # Reload the anchor
            subprocess.run(['pfctl', '-a', self.anchor_name, '-f', self.pf_file], check=True, capture_output=True)
            
            block_logger.info(f"UNBLOCKED: {ip_address}")
            logger.info(f"Successfully unblocked IP {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock IP {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip_address}: {str(e)}")
            return False
    
    def is_blocked(self, ip_address):
        """Check if an IP address is currently blocked in pf."""
        try:
            # Read anchor file and check if IP is in it
            with open(self.pf_file, 'r') as f:
                content = f.read()
                return ip_address in content
            
        except Exception as e:
            logger.error(f"Failed to check block status for IP {ip_address}: {str(e)}")
            return False
    
    def reload_blocks(self, active_blocks):
        """Reload active blocks from saved state."""
        try:
            # Clear the anchor file
            with open(self.pf_file, 'w') as f:
                f.write("# SSH Defender Blocks\n")
            
            # Add active blocks that haven't expired
            count = 0
            for ip, expiry_time in active_blocks.items():
                if datetime.fromisoformat(expiry_time) > datetime.now():
                    with open(self.pf_file, 'a') as f:
                        f.write(f"block return in quick proto tcp from {ip} to any port 22\n")
                    count += 1
            
            # Reload the anchor
            subprocess.run(['pfctl', '-a', self.anchor_name, '-f', self.pf_file], check=True, capture_output=True)
            
            logger.info(f"Reloaded {count} active IP blocks")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload IP blocks: {str(e)}")
            return False


class SSHDefenderBlocker:
    """Main SSH Defender IP blocking management class."""
    
    def __init__(self, config_path):
        """
        Initialize the SSH Defender IP blocker.
        
        Args:
            config_path (str): Path to the configuration file (YAML or JSON)
        """
        self.config_path = config_path
        self.active_blocks = {}  # IP -> expiry time
        self.whitelist = set()  # Set of whitelisted IPs/CIDRs
        self.blocker = self._get_platform_blocker()
        
        # Load configuration
        self._load_config()
        
        # Load existing blocks
        self._load_blocks()
        
        # Start expiry checker thread
        self.running = True
        self.expiry_thread = threading.Thread(target=self._check_expired_blocks)
        self.expiry_thread.daemon = True
        self.expiry_thread.start()
    
    def _get_platform_blocker(self):
        """Get the appropriate IP blocker for the current platform."""
        platform = sys.platform
        
        if platform.startswith('linux'):
            return LinuxIPBlocker()
        elif platform.startswith('win'):
            return WindowsIPBlocker()
        elif platform.startswith('darwin'):
            return MacOSIPBlocker()
        else:
            logger.error(f"Unsupported platform: {platform}")
            sys.exit(1)
    
    def _load_config(self):
        """Load configuration from YAML or JSON file."""
        try:
            if not os.path.exists(self.config_path):
                logger.warning(f"Config file {self.config_path} not found. Using empty whitelist.")
                return
            
            with open(self.config_path, 'r') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    config = yaml.safe_load(f)
                else:
                    config = json.load(f)
            
            # Load whitelist
            if 'whitelist' in config:
                for entry in config['whitelist']:
                    self.whitelist.add(entry)
                
                logger.info(f"Loaded {len(self.whitelist)} whitelist entries")
            
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
    
    def _load_blocks(self):
        """Load active blocks from storage."""
        try:
            if os.path.exists(BLOCK_STORAGE_PATH):
                with open(BLOCK_STORAGE_PATH, 'r') as f:
                    self.active_blocks = json.load(f)
                
                # Remove expired blocks
                now = datetime.now().isoformat()
                self.active_blocks = {
                    ip: expiry for ip, expiry in self.active_blocks.items()
                    if expiry > now
                }
                
                # Reload blocks in the system
                self.blocker.reload_blocks(self.active_blocks)
                
                logger.info(f"Loaded {len(self.active_blocks)} active blocks from storage")
            else:
                logger.info("No stored blocks found")
        
        except Exception as e:
            logger.error(f"Failed to load blocks: {str(e)}")
    
    def _save_blocks(self):
        """Save active blocks to storage."""
        try:
            with open(BLOCK_STORAGE_PATH, 'w') as f:
                json.dump(self.active_blocks, f)
            
            logger.debug("Saved active blocks to storage")
        
        except Exception as e:
            logger.error(f"Failed to save blocks: {str(e)}")
    
    def _check_expired_blocks(self):
        """Periodically check for and remove expired blocks."""
        while self.running:
            try:
                now = datetime.now().isoformat()
                expired_ips = []
                
                # Find expired blocks
                for ip, expiry in self.active_blocks.items():
                    if expiry <= now:
                        expired_ips.append(ip)
                
                # Remove expired blocks
                for ip in expired_ips:
                    self.unblock_ip(ip)
                    logger.info(f"Automatically unblocked expired IP: {ip}")
                
                # Save changes
                if expired_ips:
                    self._save_blocks()
                
                # Sleep for a minute
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in expiry checker: {str(e)}")
                time.sleep(60)
    
    def is_whitelisted(self, ip_address):
        """
        Check if an IP address is whitelisted.
        
        Args:
            ip_address (str): The IP address to check
            
        Returns:
            bool: True if IP is whitelisted, False otherwise
        """
        # Check exact IP match
        if ip_address in self.whitelist:
            return True
        
        # Check CIDR ranges
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for entry in self.whitelist:
                if '/' in entry:  # It's a CIDR range
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_obj in network:
                        return True
        except ValueError:
            logger.error(f"Invalid IP address or CIDR: {ip_address}")
        
        return False
    
    def block_ip(self, ip_address, duration_hours=24):
        """
        Block an IP address if it's not whitelisted.
        
        Args:
            ip_address (str): The IP address to block
            duration_hours (int): Number of hours to block the IP for
            
        Returns:
            bool: True if block was successful or IP is whitelisted, False otherwise
        """
        # Check whitelist
        if self.is_whitelisted(ip_address):
            logger.info(f"Not blocking whitelisted IP: {ip_address}")
            return True
        
        # Block the IP
        success = self.blocker.block_ip(ip_address, duration_hours)
        
        if success:
            # Update active blocks
            expiry_time = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
            self.active_blocks[ip_address] = expiry_time
            self._save_blocks()
        
        return success
    
    def unblock_ip(self, ip_address):
        """
        Unblock an IP address.
        
        Args:
            ip_address (str): The IP address to unblock
            
        Returns:
            bool: True if unblock was successful, False otherwise
        """
        success = self.blocker.unblock_ip(ip_address)
        
        if success and ip_address in self.active_blocks:
            del self.active_blocks[ip_address]
            self._save_blocks()
        
        return success
    
    def is_blocked(self, ip_address):
        """
        Check if an IP address is currently blocked.
        
        Args:
            ip_address (str): The IP address to check
            
        Returns:
            bool: True if IP is blocked, False otherwise
        """
        return self.blocker.is_blocked(ip_address)
    
    def shutdown(self):
        """Clean up resources and shut down the blocker."""
        self.running = False
        if self.expiry_thread.is_alive():
            self.expiry_thread.join(timeout=1)
        logger.info("SSH Defender Blocker shut down")


# Example usage
if __name__ == "__main__":
    # Example config file contents (save as config.yaml)
    example_config = """
    whitelist:
      - 192.168.1.0/24
      - 10.0.0.1
      - 127.0.0.1
    """
    
    # Write example config to disk
    with open('example_config.yaml', 'w') as f:
        f.write(example_config)
    
    print("Example configuration created in example_config.yaml")
    print("Whitelist entries:")
    print("  - 192.168.1.0/24 (entire subnet)")
    print("  - 10.0.0.1 (specific IP)")
    print("  - 127.0.0.1 (localhost)")
    
    print("\nUsage example (not actually executed):")
    print("defender = SSHDefenderBlocker('example_config.yaml')")
    print("defender.block_ip('45.227.255.206', duration_hours=24)")
    print("defender.unblock_ip('45.227.255.206')")
    print("defender.is_whitelisted('192.168.1.10')  # Would return True")
    print("defender.is_whitelisted('45.227.255.206')  # Would return False")
    print("defender.shutdown()")