"""
Copyright (c) 2024 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import logging as log
import socket
import sys
from ipaddress import IPv4Address, IPv6Address, ip_address
from syslog import LOG_ERR, syslog

from cisco.acl import ACL, IPv4ACL, IPv6ACL
from cli import clid
from errors import structured_output_not_supported_error

####
# Configuration
####
IPV4_ACL = "test_acl"
IPV6_ACL = "test_aclv6"
FQDN = ["example.com", "example2.com"]
# For new ACL entries created by this script:
PROTO = "ip"
SOURCE = "any"
DPORT = None
# Set to True if ACL should have implicit default deny at the end
DEFAULT_DENY = True


###
# Global vars - Do not edit
default_deny_seqno_v4 = 0
default_deny_seqno_v6 = 0
v4_seqlist = []
v6_seqlist = []

# Logging setup
log.basicConfig(format="%(asctime)s - %(message)s", level=log.INFO)


def resolve_fqdn() -> dict:
    """
    Resolve FQDN(s) and return all current IP addresses
    """
    log.info(f"Resolving {len(FQDN)} FQDNs...")
    # Since we need separate ACL for v4 and v6, we will store them in separate lists
    addresses = {}
    addresses["v4"] = []
    addresses["v6"] = []
    for domain in FQDN:
        try:
            log.info(f"Resolving: {domain}")
            resolved = socket.getaddrinfo(domain, None)
        except Exception as e:
            log.info(f"Error resolving {domain}: {e}")
            syslog(
                LOG_ERR,
                f"Error resolving domain {domain}. See script logs for details.",
            )
            continue
        # If no addresses resolved, exit - otherwise script would remove all ACL entries
        if len(resolved) == 0:
            log.info(f"Error: No addresses resolved for {domain}...")
            syslog(LOG_ERR, f"{domain} resolved to 0 addresses.")
            continue
        for address in resolved:
            # Assign /32 or /128 based on address type
            if isinstance(ip_address(address[4][0]), IPv4Address):
                if str(address[4][0] + "/32") not in addresses["v4"]:
                    addresses["v4"].append(address[4][0] + "/32")
            if isinstance(ip_address(address[4][0]), IPv6Address):
                if str(address[4][0] + "/128") not in addresses["v6"]:
                    addresses["v6"].append(address[4][0] + "/128")
        log.info(
            f"Done. {domain} resolved to {sum(len(a) for a in addresses.values())} addresses."
        )
    log.info(
        f"Completed resolving all domains. Total resolved addresses: {sum(len(a) for a in addresses.values())}"
    )
    if sum(len(a) for a in addresses.values()) == 0:
        log.info("Error: No addresses resolved. Exiting...")
        syslog(LOG_ERR, "Script resolved 0 addresses for all configured domains.")
        sys.exit(1)
    return addresses


def get_current_acl(name: str, ipver: str) -> dict:
    """
    Run `show access-list` and return list of current addresses in ACL
    """
    global default_deny_seqno_v4
    global default_deny_seqno_v6
    global v4_seqlist
    global v6_seqlist
    current_addresses = {}
    log.info(f"Getting current IP{ipver} ACL entries...")
    try:
        results = clid(f"show access-list {name}")
        results = json.loads(results)
    except structured_output_not_supported_error:
        log.info("ACL not found. Creating new ACL...")
        if ipver == "v4":
            newacl = ACL("ip", name)
        if ipver == "v6":
            newacl = ACL("ipv6", name)
        newacl.create()
        return current_addresses
    for entry in results["TABLE_ip_ipv6_mac"]["ROW_ip_ipv6_mac"]["TABLE_seqno"][
        "ROW_seqno"
    ]:
        if ipver == "v4":
            v4_seqlist.append(int(entry["seqno"]))
            # Assume any deny is a default deny
            if entry["permitdeny"] == "deny":
                default_deny_seqno_v4 = entry["seqno"]
                continue
            current_addresses[entry["seqno"]] = entry["dest_ip_prefix"]
        if ipver == "v6":
            v6_seqlist.append(int(entry["seqno"]))
            # Assume any deny is a default deny
            if entry["permitdeny"] == "deny":
                default_deny_seqno_v6 = entry["seqno"]
                continue
            current_addresses[entry["seqno"]] = entry["dest_ipv6_prefix"]
    return current_addresses


def compare_lists(resolved: list, acl: list, ipver: str) -> dict:
    """
    Compare FQDN resolved addresses & current ACL entries
    """
    log.info("Comparing resolved addresses with ACL entries...")
    add = []
    remove = {}
    for address in resolved[ipver]:
        if address not in acl.values():
            add.append(address)
    for seq, address in acl.items():
        if address not in resolved[ipver]:
            remove[seq] = address
    log.info(
        f"For IP{ipver} ACL: Resolved {len(resolved[ipver])}, Current {len(acl)}, Add {len(add)}, Remove {len(remove)}."
    )
    return {"add": add, "remove": remove}


def update_acl(changes: dict, ipver: str) -> dict:
    """
    Add / Remove ACL entries based on FQDN changes
    """
    global default_deny_seqno_v4
    global default_deny_seqno_v6
    log.info(f"Updating IP{ipver} ACL...")
    added = []
    removed = []
    protocol = PROTO
    # Get ACL object based on IP version
    log.info("Current ACL config:")
    if ipver == "v4":
        acl = IPv4ACL(IPV4_ACL)
    if ipver == "v6":
        acl = IPv6ACL(IPV6_ACL)
    if protocol == "ip" and ipver == "v6":
        protocol = "ipv6"
    # Add new entries
    for addr in changes["add"]:
        seq = find_next_seq(ipver)
        acl.permit(protocol, SOURCE, addr, dport=DPORT, sequence=seq)
        added.append(addr)
    # Remove old entries
    for seq, addr in changes["remove"].items():
        acl.delete_entry(seq)
        removed.append(addr)
    # Re-apply default deny if needed
    if DEFAULT_DENY:
        # Remove existing default deny by sequence number
        if ipver == "v4" and default_deny_seqno_v4 != 0:
            acl.delete_entry(default_deny_seqno_v4)
        if ipver == "v6" and default_deny_seqno_v6 != 0:
            acl.delete_entry(default_deny_seqno_v6)
        # Add new default deny at the end
        acl.deny(protocol, "any", "any")
    log.info(
        f"Done! IP{ipver} ACL Updated - Added {len(added)}, Removed {len(removed)}"
    )
    # Show new ACL config
    log.info("New ACL config:")
    acl.show()
    return {"add": added, "remove": removed}


def find_next_seq(ipver: str) -> int:
    """
    Find next available sequence number for ACL entry.

    By default, Cisco ACL module will increment by 10 for each new entry.
    Even if entries are deleted, they are not re-used. So if script runs long
    enough, we could run out of sequence numbers.
    """
    global v4_seqlist
    global v6_seqlist
    next_seq = 10
    if ipver == "v4":
        if len(v4_seqlist) == 0:
            v4_seqlist.append(next_seq)
            return next_seq
        while True:
            if next_seq in v4_seqlist:
                next_seq += 10
            else:
                v4_seqlist.append(next_seq)
                return next_seq
    if ipver == "v6":
        if len(v6_seqlist) == 0:
            v6_seqlist.append(next_seq)
            return next_seq
        while True:
            if next_seq in v6_seqlist:
                next_seq += 10
            else:
                v6_seqlist.append(next_seq)
                return next_seq


def send_syslog(v4: dict, v6: dict) -> None:
    """
    Send alert on any changed ACL entries
    """
    log.info("Sending syslog messages to notify ACL changes...")
    if v4:
        if len(v4["add"]) == 0 and len(v4["remove"]) == 0:
            syslog(
                LOG_ERR,
                f"IPv4 ACL: {IPV4_ACL}, FQDN: {FQDN}. No updates to ACL required.",
            )
        else:
            syslog(
                LOG_ERR,
                f"IPv4 ACL: {IPV4_ACL}, FQDN: {FQDN}, ADD: {v4['add']}, REMOVE: {v4['remove']}",
            )
    if v6:
        if len(v6["add"]) == 0 and len(v6["remove"]) == 0:
            syslog(
                LOG_ERR,
                f"IPv6 ACL: {IPV6_ACL}, FQDN: {FQDN}. No updates to ACL required.",
            )
        else:
            syslog(
                LOG_ERR,
                f"IPv6 ACL: {IPV6_ACL}, FQDN: {FQDN}, ADD: {v6['add']}, REMOVE: {v6['remove']}",
            )
    log.info("Done. Syslog messages sent.")


def run():
    log.info("FQDN Update script started")
    # Get current addresses for FQDN
    current_addresses = resolve_fqdn()
    # Get current ACL config & compare with resolved addresses
    # Then update ACL based on changes
    resultsv4 = None
    resultsv6 = None
    if IPV4_ACL:
        current_aclv4 = get_current_acl(IPV4_ACL, "v4")
        diffv4 = compare_lists(current_addresses, current_aclv4, "v4")
        resultsv4 = update_acl(diffv4, "v4")
    if IPV6_ACL:
        current_aclv6 = get_current_acl(IPV6_ACL, "v6")
        diffv6 = compare_lists(current_addresses, current_aclv6, "v6")
        resultsv6 = update_acl(diffv6, "v6")
    # Send syslog messages
    send_syslog(resultsv4, resultsv6)
    log.info("FQDN Update script finished")


if __name__ == "__main__":
    run()
