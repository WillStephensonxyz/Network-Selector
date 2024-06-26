#!/usr/bin/python3 

import click 
import pywifi 
from pywifi import const 
import netifaces 
import psutil 
import subprocess 
from rich.console import Console 
from rich.table import Table 
import time 

console = Console() 

def get_security_protocol(network): 
    if const.AKM_TYPE_WPA in network.akm: 
        return "WPA" 
    elif const.AKM_TYPE_WPAPSK in network.akm:
        return "WPAPSK" 
    elif const.AKM_TYPE_WPA2 in network.akm:
        return "WPA2" 
    elif const.AKM_TYPE_WPA2PSK in network.akm: 
        return "WPA2PSK" 
    else: 
        return "Open" 

@click.group()
def cli():
    """A tool to manage Wi-Fi and Ethernet connections.""" 
    pass 

@cli.command() 
def scan_wifi():
    """Scan for available Wi-Fi networks.""" 
    wifi = pywifi.PyWiFi() 
    iface = wifi.interfaces()[0] 
    iface.scan() 
    time.sleep(5)
    results = iface.scan_results() 
    table = Table(title="Available Wi-Fi Networks") 
    table.add_column("SSID", style="cyan", no_wrap=True)  
    table.add_column("Signal", style="magenta") 
    table.add_column("Security", style="green") 

    for network in results: 
        security = get_security_protocol(network)
        table.add_row(network.ssid, str(network.signal), security)

    console.print(table) 


@cli.command() 
@click.argument('ssid') 
@click.argument('password') 
def join_wifi(ssid, password): 
    """Join a specified network"""
    wifi = pywifi.PyWiFi
    iface = wifi.interfaces()[0] 
    iface.disconnect() 
    profile = pywifi.Profile() 
    profile.ssid = ssid 
    profile.key = password 
    profile.auth = const.AUTH_ALG_OPEN 
    profile.akm.append(const.AKM_TYPE_WPA2PSK) 
    profile.cipher = const.CIPHER_TYPE_CCMP 
    iface.remove_all_network_profiles() 
    tmp_profile = iface.add_network_profile(profile) 
    iface.connect(tmp_profile) 
    console.print(f"Attempting to connect to {ssid}...")
    time.sleep(10) 
    if iface.status() == const.IFACE_CONNECTED: 
        console.print(f"Successfully connected to {ssid}", style="green") 
    else: 
        console.print(f"Failed to connect to {ssid}", style="red") 


@cli.command() 
def ethernet_status(): 
    """Display Ethernet connection status."""
    interfaces = netifaces.interfaces() 
    table = Table(title="Ethernet Interfaces") 
    table.add_column("Interface", style="cyan", no_wrap=True) 
    table.add_column("Status", style="magenta") 
    table.add_column("IP Address", style="green") 

    for iface in interfaces: 
        addrs = netifaces.ifaddresses(iface) 
        status = "Up" if psutil.net_if_stats()[iface].isup else "Down" 
        ip = addrs[netifaces.AF_INET][0]['addr'] if netifaces.AF_INET in addrs else "N/A" 
        table.add_row(iface, status, ip) 

    console.print(table) 


if __name__ == "__main__":
    cli() 
        
