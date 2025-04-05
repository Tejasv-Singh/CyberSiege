#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH Brute Force Alert System

This module provides functions to send real-time alerts when SSH brute force attacks are detected.
Alerts are sent via Slack webhooks and email (SMTP).
"""

import json
import socket
import requests
import smtplib
import geoip2.database
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ssh_alert_system')

def get_geo_location(ip_address, geoip_db_path):
    """
    Get geolocation information for an IP address using MaxMind GeoIP2 database.
    
    Args:
        ip_address (str): The IP address to look up
        geoip_db_path (str): Path to the MaxMind GeoIP2 database file
        
    Returns:
        dict: Dictionary containing geolocation information or None if lookup fails
    """
    try:
        with geoip2.database.Reader(geoip_db_path) as reader:
            response = reader.city(ip_address)
            return {
                'country': response.country.name,
                'country_iso': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip_address}: {str(e)}")
        return None

def get_reverse_dns(ip_address):
    """
    Perform a reverse DNS lookup for an IP address.
    
    Args:
        ip_address (str): The IP address to look up
        
    Returns:
        str: The hostname for the IP address or original IP if lookup fails
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return ip_address

def send_slack_alert(webhook_url, alert_data, geoip_db_path):
    """
    Send an alert to Slack about a potential SSH brute force attack.
    
    Args:
        webhook_url (str): The Slack webhook URL
        alert_data (dict): Data about the attack
        geoip_db_path (str): Path to the MaxMind GeoIP2 database file
        
    Returns:
        bool: True if alert was sent successfully, False otherwise
    """
    try:
        # Get geolocation information
        geo_info = get_geo_location(alert_data['attacker_ip'], geoip_db_path)
        geo_text = "Unknown location"
        
        if geo_info:
            geo_text = f"{geo_info.get('city', 'Unknown city')}, {geo_info.get('country', 'Unknown country')} ({geo_info.get('country_iso', '')})"
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(alert_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        
        # Create Slack message payload
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 SSH Brute Force Attack Detected 🚨"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Attacker IP:*\n{alert_data['attacker_ip']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Timestamp:*\n{timestamp}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Target Username:*\n{alert_data['target_username']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Failed Attempts:*\n{alert_data['failed_attempts']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Location:*\n{geo_text}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Server:*\n{alert_data['server_name']}"
                        }
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "SSH Brute Force Defender | *<!here>*"
                        }
                    ]
                }
            ]
        }
        
        # Send request to Slack webhook
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        
        logger.info(f"Slack alert sent for IP {alert_data['attacker_ip']}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {str(e)}")
        return False

def send_email_alert(smtp_config, alert_data, geoip_db_path):
    """
    Send an email alert about a potential SSH brute force attack.
    
    Args:
        smtp_config (dict): SMTP configuration including server, port, username, password, and recipients
        alert_data (dict): Data about the attack
        geoip_db_path (str): Path to the MaxMind GeoIP2 database file
        
    Returns:
        bool: True if alert was sent successfully, False otherwise
    """
    try:
        # Get geolocation information
        geo_info = get_geo_location(alert_data['attacker_ip'], geoip_db_path)
        geo_text = "Unknown location"
        
        if geo_info:
            geo_text = f"{geo_info.get('city', 'Unknown city')}, {geo_info.get('country', 'Unknown country')} ({geo_info.get('country_iso', '')})"
        
        # Get reverse DNS
        reverse_dns = get_reverse_dns(alert_data['attacker_ip'])
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(alert_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        
        # Determine severity level and color
        severity = "CRITICAL" if alert_data['failed_attempts'] >= 10 else "WARNING"
        color = "#FF0000" if severity == "CRITICAL" else "#FFA500"  # Red for critical, orange for warning
        
        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[{severity}] SSH Brute Force Attack Detected"
        msg['From'] = smtp_config['username']
        msg['To'] = ", ".join(smtp_config['recipients'])
        
        # Create HTML email content
        html = f"""
        <html>
          <head>
            <style>
              body {{ font-family: Arial, sans-serif; }}
              .container {{ padding: 20px; }}
              .header {{ background-color: {color}; color: white; padding: 10px; font-size: 20px; }}
              .details {{ margin-top: 20px; }}
              table {{ border-collapse: collapse; width: 100%; }}
              th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
              th {{ background-color: #f2f2f2; }}
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                SSH Brute Force Attack Detection: {severity}
              </div>
              <div class="details">
                <p>A potential SSH brute force attack has been detected with the following details:</p>
                <table>
                  <tr>
                    <th>Attacker IP</th>
                    <td>{alert_data['attacker_ip']}</td>
                  </tr>
                  <tr>
                    <th>Reverse DNS</th>
                    <td>{reverse_dns}</td>
                  </tr>
                  <tr>
                    <th>Geolocation</th>
                    <td>{geo_text}</td>
                  </tr>
                  <tr>
                    <th>Target Username</th>
                    <td>{alert_data['target_username']}</td>
                  </tr>
                  <tr>
                    <th>Failed Attempts</th>
                    <td>{alert_data['failed_attempts']}</td>
                  </tr>
                  <tr>
                    <th>Timestamp</th>
                    <td>{timestamp}</td>
                  </tr>
                  <tr>
                    <th>Server</th>
                    <td>{alert_data['server_name']}</td>
                  </tr>
                </table>
                <p>Please take appropriate action to secure your system.</p>
              </div>
            </div>
          </body>
        </html>
        """
        
        # Attach HTML content
        msg.attach(MIMEText(html, 'html'))
        
        # Connect to SMTP server and send email
        with smtplib.SMTP(smtp_config['server'], smtp_config['port']) as server:
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            server.send_message(msg)
        
        logger.info(f"Email alert sent for IP {alert_data['attacker_ip']}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email alert: {str(e)}")
        return False

def send_alerts(alert_data, config):
    """
    Process alert data and send both Slack and email alerts.
    
    Args:
        alert_data (dict): Data about the attack
        config (dict): Configuration for alerts including Slack webhook URL, SMTP config, and GeoIP DB path
        
    Returns:
        dict: Results of alert sending attempts
    """
    results = {
        'slack': False,
        'email': False
    }
    
    # Send Slack alert
    if 'slack_webhook_url' in config:
        results['slack'] = send_slack_alert(
            config['slack_webhook_url'],
            alert_data,
            config['geoip_db_path']
        )
    
    # Send email alert
    if 'smtp_config' in config:
        results['email'] = send_email_alert(
            config['smtp_config'],
            alert_data,
            config['geoip_db_path']
        )
    
    return results

# Example usage
if __name__ == "__main__":
    # Example alert data
    example_alert_data = {
        "attacker_ip": "45.227.255.206",
        "timestamp": 1617285052,  # Unix timestamp
        "target_username": "root",
        "failed_attempts": 15,
        "server_name": "prod-web-01"
    }
    
    # Example configuration
    example_config = {
        "slack_webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        "smtp_config": {
            "server": "smtp.gmail.com",
            "port": 587,
            "username": "alerts@example.com",
            "password": "your_password_here",
            "recipients": ["admin@example.com", "security@example.com"]
        },
        "geoip_db_path": "/path/to/GeoLite2-City.mmdb"
    }
    
    # Print example usage
    print("Example alert data:")
    print(json.dumps(example_alert_data, indent=2))
    print("\nExample configuration:")
    print(json.dumps(example_config, indent=2))
    
    # Uncomment the line below to actually send alerts when running this file directly
    # results = send_alerts(example_alert_data, example_config)
    # print(f"Alert sending results: {results}")