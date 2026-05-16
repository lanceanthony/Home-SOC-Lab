# Phase 1 — Network Foundation

## Overview
Configured pfSense CE 2.7.2 as the perimeter firewall and gateway for the SOC lab internal network.

## Network Design
| Interface | IP | Purpose |
|-----------|-----|---------|
| WAN | DHCP (NAT) | Internet access for pfSense only |
| LAN | 192.168.10.1/24 | SOC-Lab-Network internal gateway |

## Steps Completed
1. Downloaded pfSense CE 2.7.2 ISO
2. Created VirtualBox VM (1GB RAM, 10GB disk)
3. Configured Adapter 1: NAT, Adapter 2: Internal Network (SOC-Lab-Network)
4. Completed pfSense setup wizard — set LAN IP to 192.168.10.1
5. Enabled DHCP server on LAN (range: 192.168.10.100–200)
6. Verified connectivity from other VMs

## Screenshots
See `/screenshots/` folder.
