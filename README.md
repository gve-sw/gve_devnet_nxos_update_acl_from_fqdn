# Cisco Nexus ACL Update from FQDN

The purpose of this script is to update access lists on a Nexus switch based on resolved IPs of a domain. The code utilizes Nexus on-box Python to run directly from the device & modify it's own configuration.

This script will:

- Resolve current addresses for a specified FQDN
- Query current access list entries
- Compare each to determine if IPs need to be added / removed
- Apply ACL changes
- Notify changes via syslog

## Contacts

- Matt Schmitz (<mattsc@cisco.com>)

## Solution Components

- Cisco Nexus 9000v (Tested on NX-OS 10.3(1) with Python 3.7.10)

> Note: This code requires an NX-OS software release that is capable of using Python 3

## Installation/Configuration

### **Step 1 - Clone repo**

```bash
git clone https://github.com/gve-sw/gve_devnet_nxos_update_acl_from_fqdn
```

### **Step 2 - Configure Script**

In order to use this script, some configuration is required. Within the script header, there is a section of variables to configure.

```python
IPV4_ACL = "example_acl_v4"
IPV6_ACL = "example_acl_v6"
FQDN = ["example.com", "example.org"]
PROTO = "ip"
SOURCE = "any"
DPORT = None
DEFAULT_DENY = True
```

- **IPV4_ACL** - Name of IPv4 ACL for script to manage. Leave blank if only using IPv6
- **IPV6_ACL** - Name of IPv6 ACL for script to manage. Leave blank if only using IPv4
- **FQDN** - List of fully-qualified domain name(s) to monitor. At least one is required, but multiple may be specified
- **PROTO** - IP protocol for new ACL entries. Example: `ip`, `tcp`, or `udp`
- **SOURCE** - Specify source address or network for ACL entries
- **DPORT** - Optional destination port to allow. Leave at `None` if port should be `any`
- **DEFAULT_DENY** - Set to `True` if an explicit default deny rule is desired. This will tell the script to remove/re-apply the deny, to ensure other rules are placed before the deny.

### **Step 3 - Copy script to Nexus**

After configuration, copy the `update_acl_from_fqdn.py` file to the remote Nexus device bootflash. This can be accomplished via the standard methods: TFTP, HTTP, FTP, SCP, etc

### **Step 4 - Ensure Syslog is configured**

The script relies on the Nexus configuration for syslog. Any messages sent via the script will be forwarded to the local Nexus syslog process. These syslog messages will be available in the standard device logs, viewable via the `show logging` command.

If alerts need to be received by a remote syslog host, please ensure that one is configured on the switch.

Example:

```text
nx(config)# logging server 192.0.2.50
```

### **Step 4 - Ensure DNS servers are configured**

The script relies on the Nexus configuration for DNS. Any DNS lookups through the script are processed by whichever DNS servers are configured on the local Nexus device.

Without DNS configuration on the Nexus switch, this script will fail to resolve domains.

Example:

```text
nx(config)# ip domain-lookup
nx(config)# ip name-server 192.0.2.53
nx(config)# ! Optionally set source interface for DNS queries
nx(config)# ip dns source-interface mgmt0
```

## Usage

### **Run Manually**

To test the script, you may wish to execute it manually. Once the script is copied to the device, it can be run with the following command:

```text
nx# python3 bootflash:/update_acl_from_fqdn.py
```

This will output the script logs directly to the Nexus terminal, which can be helpful for troubleshooting.

### **Create Scheduled task**

Using the built-in Nexus task scheduler, we can allow the script to execute on regular intervals. This will define how frequently the script will attempt to resolve the specified FQDN and make ACL adjustments.

First, enable the scheduler feature:

```text
nx(config)# feature scheduler
```

Then, create a job to run the script:

```text
nx(config)# scheduler job name job_update_acl
nx(config-job)# python3 bootflash:/update_acl_from_fqdn.py
```

Finally, create a schedule to execute the script on the desired interval:

```text
nx(config)# scheduler schedule name schedule_update_acl
nx(config-schedule)# job name job_update_acl
nx(config-schedule)# time start now repeat 0:0:5
```

For example, the above schedule begins immediately & executes the Python script every 5 minutes.

Upon any ACL changes, syslog messages will be generated like the example shown below:

```text
2024 Apr  1 17:04:47 nexus-lab %USER-3-SYSTEM_MSG: IPv4 ACL: example_acl_v4, FQDN: example.com, ADD: ['203.0.113.10/32', '203.0.113.20/32'], REMOVE: ['203.0.113.30/32'] - /update_acl_from_fqdn.py
2024 Apr  1 17:04:47 nexus-lab %USER-3-SYSTEM_MSG: IPv6 ACL: example_acl_v6, FQDN: example.com, ADD: ['2001:DB8::113/128', '2001:DB8::1234/128'], REMOVE: [] - /update_acl_from_fqdn.py
```

## Troubleshooting

To check the configured tasks & see last execution status, use `show scheduler`:

```text
nx(config)# show scheduler schedule
Schedule Name       : schedule_update_acl
--------------------------
User Name           : admin
Schedule Type       : Run every 0 Days 0 Hrs 5 Mins
Start Time          : Mon Nov 13 16:53:45 2023
Last Execution Time : Mon Nov 13 17:39:45 2023
Last Completion Time: Mon Nov 13 17:39:46 2023
Execution count     : 47
-----------------------------------------------
     Job Name            Last Execution Status
-----------------------------------------------
job_update_acl                      Success (0)
```

If the `Last Execution Status` above shows an error, check the script logs with `show scheduler logfile`. The below example demonstates a successful execution:

```text
nx(config)# show scheduler logfile
==============================================================================
Job Name       : job_update_acl                      Job Status: Success (0)
Schedule Name  : schedule_update_acl                              User Name : admin
Completion time: Mon Nov 13 17:42:46 2023
--------------------------------- Job Output ---------------------------------

`python3 bootflash:/update_acl_from_fqdn.py`
FQDN Update script started
Resolving FQDN: google.com
Done. FQDN resolved to 2 addresses.
Getting current IPv4 ACL entries...
Comparing resolved addresses with ACL entries...
For IPv4 ACL: Resolved 1, Current 2, Add 1, Remove 2.
Updating IPv4 ACL...

IP access list example_acl_v4
        10 permit ip any 203.0.113.10/32 
        20 permit ip any 203.0.113.20/32 
        30 deny ip any any 

Done! IPv4 ACL Updated - Added 1, Removed 2

Getting current IPv6 ACL entries...
Comparing resolved addresses with ACL entries...
For IPv6 ACL: Resolved 1, Current 2, Add 1, Remove 2.
Updating IPv6 ACL...

IPv6 access list example_acl_v6
        10 permit ipv6 any 2001:DB8::113/128 
        20 permit ipv6 any 2001:DB8::1234/128 
        30 deny ipv6 any any 

Done! IPv6 ACL Updated - Added 1, Removed 2

Sending syslog messages to notify ACL changes...
Done. Syslog messages sent.
FQDN Update script finished
==============================================================================
```

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER

<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
