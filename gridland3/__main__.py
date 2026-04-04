#!/usr/bin/env python3
"""
GRIDLAND - Real Security Scanner
Clean implementation based on proven CamXploit.py functionality
"""
print("hello")
import socket
import threading
import requests
import ipaddress
import time
import json
import warnings
import click
import logging
import os
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.auth import HTTPBasicAuth

# Suppress SSL warnings for embedded devices
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# New modular imports
from lib.core import ScanTarget
from lib.network import scan_ports

# Configure comprehensive logging
def setup_logging(target_name: str = None) -> logging.Logger:
    """Setup detailed logging for scan operations"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if target_name:
        # Replace dots and slashes for safe filename
        safe_target = target_name.replace(".", "_").replace("/", "_")
        log_filename = f"gridland_scan_{safe_target}_{timestamp}.log"
    else:
        log_filename = f"gridland_scan_{timestamp}.log"
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    log_path = os.path.join('logs', log_filename)
    
    # Configure logger
    logger = logging.getLogger('gridland')
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler for detailed logs
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler for user feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Detailed formatter for file
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # Simple formatter for console
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"=== GRIDLAND SCAN SESSION STARTED ===")
    logger.info(f"Target: {target_name}")
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Log file: {log_path}")
    logger.info(f"=" * 50)
    
    return logger


# TODO: The credential testing and stream discovery logic still needs to be
# deconstructed and moved into plugins. For now, we will keep the old
# methods here and have the CLI call them directly.

# Comprehensive camera port list - CamXploit.py + GRIDLAND superset (685 unique ports)
CAMERA_PORTS = [
    # Standard web ports
    80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    
    # RTSP ports
    554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
    
    # RTMP ports
    1935, 1936, 1937, 1938, 1939,
    
    # Custom camera ports
    37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
    37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800,
    
    # ONVIF ports
    3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
    
    # VLC streaming ports
    8100, 8110, 8120, 8130, 8140, 8150, 8160, 8170, 8180, 8190,
    
    # Common alternative ports
    5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010,
    6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010,
    7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
    9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
    
    # Additional common ports
    8888, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896, 8897, 8898, 8899,
    9999, 9998, 9997, 9996, 9995, 9994, 9993, 9992, 9991, 9990,
    
    # MMS ports
    1755, 1756, 1757, 1758, 1759, 1760,
    
    # Custom ranges
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010,
    11000, 11001, 11002, 11003, 11004, 11005, 11006, 11007, 11008, 11009, 11010,
    12000, 12001, 12002, 12003, 12004, 12005, 12006, 12007, 12008, 12009, 12010,
    13000, 13001, 13002, 13003, 13004, 13005, 13006, 13007, 13008, 13009, 13010,
    14000, 14001, 14002, 14003, 14004, 14005, 14006, 14007, 14008, 14009, 14010,
    15000, 15001, 15002, 15003, 15004, 15005, 15006, 15007, 15008, 15009, 15010,
    20000, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010,
    21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010,
    22000, 22001, 22002, 22003, 22004, 22005, 22006, 22007, 22008, 22009, 22010,
    23000, 23001, 23002, 23003, 23004, 23005, 23006, 23007, 23008, 23009, 23010,
    24000, 24001, 24002, 24003, 24004, 24005, 24006, 24007, 24008, 24009, 24010,
    25000, 25001, 25002, 25003, 25004, 25005, 25006, 25007, 25008, 25009, 25010,
    30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009, 30010,
    31000, 31001, 31002, 31003, 31004, 31005, 31006, 31007, 31008, 31009, 31010,
    32000, 32001, 32002, 32003, 32004, 32005, 32006, 32007, 32008, 32009, 32010,
    33000, 33001, 33002, 33003, 33004, 33005, 33006, 33007, 33008, 33009, 33010,
    34000, 34001, 34002, 34003, 34004, 34005, 34006, 34007, 34008, 34009, 34010,
    35000, 35001, 35002, 35003, 35004, 35005, 35006, 35007, 35008, 35009, 35010,
    36000, 36001, 36002, 36003, 36004, 36005, 36006, 36007, 36008, 36009, 36010,
    37000, 37001, 37002, 37003, 37004, 37005, 37006, 37007, 37008, 37009, 37010,
    38000, 38001, 38002, 38003, 38004, 38005, 38006, 38007, 38008, 38009, 38010,
    39000, 39001, 39002, 39003, 39004, 39005, 39006, 39007, 39008, 39009, 39010,
    40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009, 40010,
    41000, 41001, 41002, 41003, 41004, 41005, 41006, 41007, 41008, 41009, 41010,
    42000, 42001, 42002, 42003, 42004, 42005, 42006, 42007, 42008, 42009, 42010,
    43000, 43001, 43002, 43003, 43004, 43005, 43006, 43007, 43008, 43009, 43010,
    44000, 44001, 44002, 44003, 44004, 44005, 44006, 44007, 44008, 44009, 44010,
    45000, 45001, 45002, 45003, 45004, 45005, 45006, 45007, 45008, 45009, 45010,
    46000, 46001, 46002, 46003, 46004, 46005, 46006, 46007, 46008, 46009, 46010,
    47000, 47001, 47002, 47003, 47004, 47005, 47006, 47007, 47008, 47009, 47010,
    48000, 48001, 48002, 48003, 48004, 48005, 48006, 48007, 48008, 48009, 48010,
    49000, 49001, 49002, 49003, 49004, 49005, 49006, 49007, 49008, 49009, 49010,
    50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010,
    51000, 51001, 51002, 51003, 51004, 51005, 51006, 51007, 51008, 51009, 51010,
    52000, 52001, 52002, 52003, 52004, 52005, 52006, 52007, 52008, 52009, 52010,
    53000, 53001, 53002, 53003, 53004, 53005, 53006, 53007, 53008, 53009, 53010,
    54000, 54001, 54002, 54003, 54004, 54005, 54006, 54007, 54008, 54009, 54010,
    55000, 55001, 55002, 55003, 55004, 55005, 55006, 55007, 55008, 55009, 55010,
    56000, 56001, 56002, 56003, 56004, 56005, 56006, 56007, 56008, 56009, 56010,
    57000, 57001, 57002, 57003, 57004, 57005, 57006, 57007, 57008, 57009, 57010,
    58000, 58001, 58002, 58003, 58004, 58005, 58006, 58007, 58008, 58009, 58010,
    59000, 59001, 59002, 59003, 59004, 59005, 59006, 59007, 59008, 59009, 59010,
    60000, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010,
    61000, 61001, 61002, 61003, 61004, 61005, 61006, 61007, 61008, 61009, 61010,
    62000, 62001, 62002, 62003, 62004, 62005, 62006, 62007, 62008, 62009, 62010,
    63000, 63001, 63002, 63003, 63004, 63005, 63006, 63007, 63008, 63009, 63010,
    64000, 64001, 64002, 64003, 64004, 64005, 64006, 64007, 64008, 64009, 64010,
    65000, 65001, 65002, 65003, 65004, 65005, 65006, 65007, 65008, 65009, 65010
]

from lib.plugin_manager import PluginManager

def run_single_target_scan(ip: str, aggressive: bool, threads: int, logger: logging.Logger = None) -> Optional[ScanTarget]:
    """Orchestrates a scan against a single target IP."""
    if not logger:
        logger = logging.getLogger('gridland')
    
    logger.info(f"\n[🎯] Scanning {ip}")
    logger.debug(f"Parameters: aggressive={aggressive}, threads={threads}")
    target = ScanTarget(ip=ip)

    # Step 1: Port scan
    logger.info(f"[🔍] Scanning {ip} for open ports...")
    logger.debug(f"Scanning {len(CAMERA_PORTS)} camera-specific ports")
    
    try:
        target.open_ports = scan_ports(ip, CAMERA_PORTS, max_threads=threads)
        logger.debug(f"Port scan completed. Found {len(target.open_ports)} open ports")
        
        if not target.open_ports:
            logger.info("[❌] No open ports found")
            logger.debug("Scan terminated - no open ports detected")
            return None

        logger.info(f"[✅] Found {len(target.open_ports)} open ports: {[p.port for p in target.open_ports]}")

    except Exception as e:
        logger.error(f"Port scan failed: {str(e)}")
        logger.debug(f"Port scan exception details", exc_info=True)
        return None

    manager = PluginManager()
    fingerprint = {}

    # Step 2: Fingerprint Scanning (Intelligence Gathering)
    logger.info(f"[📷] Fingerprinting device at {ip}...")
    try:
        fingerprint_findings = manager.run_plugin_by_name("FingerprintScannerPlugin", target)
        if fingerprint_findings and fingerprint_findings[0].category == 'fingerprint':
            fingerprint = fingerprint_findings[0].data
            target.brand = fingerprint.get('vendor')
            target.device_type = fingerprint.get('product')
            logger.info(f"[✅] Device identified: {target.brand or 'Unknown'} {target.device_type or ''}")
            logger.debug(f"Fingerprint successful: {fingerprint}")
        else:
            logger.info(f"[⚠️] Could not identify specific device type")

    except Exception as e:
        logger.error(f"Device fingerprinting failed: {str(e)}")
        logger.debug(f"Device fingerprinting exception details", exc_info=True)

    if aggressive:
        # Step 3: Run all other plugins with intelligence
        logger.info(f"[🔌] Running intelligence-led aggressive scans on {ip}...")
        try:
            # Run all plugins, passing in the fingerprint intelligence
            findings = manager.run_all_plugins(target, fingerprint=fingerprint)
            logger.debug(f"Plugin execution completed. Found {len(findings)} findings")

            # Process findings and add to target
            for finding in findings:
                # Skip the fingerprint finding since we already processed it
                if finding.category == "fingerprint":
                    continue

                logger.info(f"   [+] {finding.category}: {finding.description}")
                logger.debug(f"Finding details: {finding.__dict__}")
                
                if finding.category == "credential":
                    if finding.data and "username" in finding.data and "password" in finding.data:
                        creds_key = f"{finding.data['username']}:{finding.data['password']}"
                        target.credentials[creds_key] = finding.url or f"{ip}:{finding.port}"
                        logger.debug(f"Added credential: {creds_key}")

                elif finding.category == "stream":
                    if finding.url:
                        target.streams.append(finding.url)
                        logger.debug(f"Added stream: {finding.url}")

                else:
                    target.vulnerabilities.append(finding.description)
                    logger.debug(f"Added vulnerability: {finding.description}")
                    
        except Exception as e:
            logger.error(f"Plugin execution failed: {str(e)}")
            logger.debug(f"Plugin execution exception details", exc_info=True)

    logger.info(f"[✅] Scan complete for {ip}")
    logger.debug(f"Final scan results: {len(target.open_ports)} ports, {len(target.credentials)} credentials, {len(target.streams)} streams, {len(target.vulnerabilities)} vulnerabilities")
    return target

# CLI Implementation
@click.group()
def gridland():
    """GRIDLAND - Real Network Security Scanner"""
    pass

@gridland.command()
@click.argument('target')
@click.option('--aggressive', '-a', is_flag=True, help='Enable credential testing and stream discovery')
@click.option('--threads', '-t', default=100, help='Number of threads')
@click.option('--output', '-o', help='Output JSON file')
def scan(target, aggressive, threads, output):
    """Scan single IP or network range"""
    logger = setup_logging(target)
    results = []
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            logger.info(f"\n[🌐] Scanning network: {target}")
            logger.debug(f"Network contains {network.num_addresses} addresses")
            for ip_obj in network.hosts():
                ip = str(ip_obj)
                result = run_single_target_scan(ip, aggressive, threads, logger)
                if result:
                    results.append(result)
            logger.info(f"\n[📊] Found {len(results)} devices with open ports")
        else:
            result = run_single_target_scan(target, aggressive, threads, logger)
            if result:
                results.append(result)
        
        # Display results
        for result in results:
            logger.info(f"\n🎯 {result.ip}")
            logger.info(f"   📡 Open Ports: {', '.join(map(str, [p.port for p in result.open_ports]))}")
            if result.device_type:
                logger.info(f"   📷 Device: {result.device_type} ({result.brand})")
            if result.credentials:
                logger.info(f"   🔑 CREDENTIALS FOUND:")
                for k, v in result.credentials.items():
                    logger.info(f"      🔥 {v}")
            if result.streams:
                logger.info(f"   🎥 STREAMS FOUND:")
                for stream in result.streams:
                    logger.info(f"      📺 {stream}")
        
        # Save to file if requested
        if output and results:
            # Note: The data saved is not as rich as the original ScanTarget object yet
            data = [r.__dict__ for r in results]
            with open(output, 'w') as f:
                json.dump(data, f, indent=2, default=lambda o: o.__dict__)
            logger.info(f"\n[📄] Results saved to {output}")
            logger.debug(f"Saved {len(results)} results to {output}")
    
    except KeyboardInterrupt:
        logger.info("\n[⏹️] Scan stopped by user")
        logger.debug("Scan interrupted by user with KeyboardInterrupt")

@gridland.command()
@click.argument('target')
def quick(target):
    """Quick aggressive scan"""
    logger = setup_logging(target)
    result = run_single_target_scan(target, True, 100, logger)
    
    if result:
        logger.info(f"\n🎯 {result.ip} - {len(result.open_ports)} open ports")
        if result.device_type:
            logger.info(f"📷 Device: {result.device_type} ({result.brand})")
        if result.credentials:
            logger.info(f"🔥 CREDENTIALS: {list(result.credentials.values())}")
        if result.streams:
            logger.info(f"📺 STREAMS: {len(result.streams)} found")
    else:
        logger.info(f"❌ No open ports on {target}")

if __name__ == '__main__':
    gridland()