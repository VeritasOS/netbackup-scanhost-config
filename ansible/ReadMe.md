# Scan host configuration using ansible
    Version: 1.0

## Description
- This utility installs and configures the prerequisites required to run a malware scan on the scan host (RHEL (8.x, 9.x) / Windows Server 2016 and above).
- Additionally, this utility can be used to install `NetBackup Malware Scanner` on the scan host.
- The following would be installed/configured by the utility on the scan hosts (requires internet connectivity)
    1. Linux scan hosts:
        <ul>
        <li>Prerequisites installed: libnsl, NFS client, SMB client. </li>
        <li>Configuration: Non root user creation. </li>
        </ul>
    2. Windows scan hosts:
        <ul>
        <li> Prerequisites installed: OpenSSH, NFS-Client, <a href="https://aka.ms/vs/17/release/vc_redist.x64.exe"> VC Runtime </a>. </li>
        <li> Configurations: Non-administrator user creation. </li>
        </ul>

## Prerequisites to be present on the ansible controller node (node on which this utility runs)
- RHEL Version = 8.x, 9.x
- ansible      = 2.16.2 and above
- python       = 3.11.x (required to run ansible 2.16.x)
- sshpass      = 1.x
- pywinrm      = 0.4.x
- requests     = 2.31.x (optional)
- SSH must be allowed to the `ansible_user` in case of linux scan hosts.
- Winrm connectivity should be allowed to the `ansible_user` in case of windows hosts.

> **_NOTE:_** Run `install_ansible.sh` for installing above prerequisites on the ansible controller node.

## Steps to configure scan host
```
1. Clone the repository from GitHub and move it to your Ansible Control Host:
    git clone https://github.com/VeritasOS/netbackup-scanhost-config.git
2. By default, the host key checking would happen before configuring the scan host.
    To add the fingerprint of the scan host for Linux hosts, perform the following:
        1. `ssh-keyscan -H {{HOST}} >> ~/.ssh/known_hosts` or manually perform SSH to the scan host.
3. Provide the scan host details in the `inventory/hosts.yml` file. Refer `Terminologies` section for the complete list of options.
    `install_avira`: Installs avira if set to `True`, defaults to False.
    `avira_package_path`:(Optional) Local absolute path to the `NetBackup Malware Scanner` zip package (NBAntimalwareClient) which is available on the Veritas download center.
    `ansible_user`: scan host username, This user should be a user with root/Administrator privileges.
    `ansible_ssh_pass`: scan host password.
4. Run the following command to run the playbook
    ansible-playbook playbook.yml
5. Use credentials displayed at the end of script to register the scan host to netbackup primary server.
```

## Minimal hosts.yml file for Linux
```
all:
  vars:
    install_avira: True
    avira_package_path: <local_absolute_path_to_the_NBAntiMalwareClient_x.y.zip>
    scan_user: scanuser
    scan_group: scangroup
    scan_user_password: scanUserPassw0rd

linuxScanHosts:
  vars:
    configure_nfs_client: True
    configure_smb_client: True
  hosts:
    <ip1/hostname1>:
      ansible_user: <username>
      ansible_ssh_pass: <password>
```

## Minimal hosts.yml file for Windows
```
all:
  vars:
    install_avira: True
    avira_package_path: <local_absolute_path_to_the_NBAntiMalwareClient_x.y.zip>
    scan_user: scanuser
    scan_group: scangroup
    scan_user_password: scanUserPassw0rd

windowsScanHosts:
  vars:
    ansible_connection:  winrm
    ansible_winrm_port:  5985
    ansible_winrm_transport: ntlm
    ansible_winrm_server_cert_validation: validate

    configure_nfs: True
    install_vc_runtime: True
    override_openssh: False
    openssh_download_url: "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip"
    configure_scan_host_for_vmware: false
  hosts:
    <ip1/hostname1>:
      ansible_user: <username>
      ansible_ssh_pass: <password>

```

## Terminologies
### Common for all platforms (inventory/hosts.yml)
| Parameter name          | Default value (If applicable)           | Descripton |
| --------------------|-----------------------------------------|---------|
| install_avira       | False                                    | Installs `NetBackup Malware Scanner` if set to True|
| avira_package_path  |  | Local absolute path of the NetBackup Malware Scanner package|
| scan_user           | scanuser                                | The user will be created if it does not exist on the scan host and NetBackup Malware Scanner will be configured using the same user|
| scan_group          | scangroup                               | This group would be created on the requested host if it does not exist and `scan_user` will be added in the same group |
| scan_user_password  | scanUserPassw0rd                        | This would be the password for `scan_user`, if not provided then password would not be set |

### Linux
| Parameter name              | Default value (If applicable) | Descripton                                                                                                 |
|-------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| configure_nfs_client      |  True                          | Installs `nfs-utils` package using `yum` if the value is `True`                                           |
| configure_smb_client      |  True                        | Installs `cifs-utils` package using `yum` if the value is `True`                                           |                                                                 |

### Windows
| Parameter name                        | Default value (If applicable) | Descripton                                                                                                       |
|-----------------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------------|
| configure_nfs                    |  True                        | Enables `NFS-Client` feature if the value is `True`                                                              |
| install_vc_runtime               | True                         | Installs `vc-runtime` if the value is `True`.                |
| override_openssh                 | False                         | Overrides openssh configuration if the value is `True`                                                           |
| openssh_download_url             | [OPENSSH](https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip) | Default URL from which the OPENSSH package would be installed |
| configure_scan_host_for_vmware                         | false                          | NFS user identity would be set to 0 if value is `True` else would set to `1000`                                          |
| ansible_connection               | winrm                         | Connection is used for connecting                                                                 |
| ansible_winrm_port               | 5985                          | Port used for connecting, this port should be open on the scan host.                                                                        |
| ansible_winrm_transport          | ntlm                          | Transport used for connecting                                                                       |
| ansible_winrm_server_cert_validation |   validate             | Default cert validation would happen before connecting, if set to `ignore` then the cert validation would not happen |

### Configuration terms (ansible.cfg)
| Parameter name              | Default value (If applicable) | Descripton                                                                                                 |
|-------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------|
| host_key_checking       | True                          | If `False` host key checking would not happen.
| inventory           | `inventory/hosts.yml`         | Default inventory path to be used.|
| log_path            | ansible_log.rb                | Default location for storing logs when the script runs.|
| always              | False                          | Logs the changed part when the task runs.|

### Additional details
1. To disable host key checking (Not recommended)
    1. For Linux scan hosts: set `host_key_checking` to `False` in `ansible.cfg`.
    2. For Windows scan hosts: set `ansible_winrm_server_cert_validation` to `ignore` in `inventory/hosts.yml`

## Legal Notice
Legal Notice
Copyright © 2024 Veritas Technologies LLC. All rights reserved.
Veritas, the Veritas Logo, and NetBackup are trademarks or registered trademarks of Veritas Technologies LLC or its affiliates in the U.S. and other countries. Other names may be trademarks of their respective owners.
This product may contain third-party software for which Veritas is required to provide attribution to the third party ("Third-party Programs"). Some of the Third-party Programs are available under open-source or free software licenses. The License Agreement accompanying the Software does not alter any rights or obligations you may have under those open-source or free software licenses. Refer to the Third-party Legal Notices document accompanying this Veritas product or available at: https://www.veritas.com/about/legal/license-agreements
The product described in this document is distributed under licenses restricting its use, copying, distribution, and decompilation/reverse engineering. No part of this document may be reproduced in any form by any means without prior written authorization of Veritas Technologies LLC and its licensors, if any.
THE DOCUMENTATION IS PROVIDED "AS IS" AND ALL EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT, ARE DISCLAIMED, EXCEPT TO THE EXTENT THAT SUCH DISCLAIMERS ARE HELD TO BE LEGALLY INVALID. VERITAS TECHNOLOGIES LLC SHALL NOT BE LIABLE FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES IN
CONNECTION WITH THE FURNISHING, PERFORMANCE, OR USE OF THIS
DOCUMENTATION. THE INFORMATION CONTAINED IN THIS DOCUMENTATION IS SUBJECT TO CHANGE WITHOUT NOTICE.

The Licensed Software and Documentation are deemed to be commercial computer software as defined in FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer Software - Restricted Rights" and DFARS 227.7202, et seq. "Commercial Computer Software and Commercial Computer Software Documentation," as applicable, and any successor regulations, whether delivered by Veritas as on-premises or hosted services. Any use, modification, reproduction release, performance, display or disclosure
of the Licensed Software and Documentation by the U.S. Government shall be solely by the terms of this Agreement.
Veritas Technologies LLC
2625 Augustine Drive
Santa Clara, CA 95054
http://www.veritas.com

## Third-Party Legal Notices
This Veritas product may contain third-party software for which Veritas is required to provide attribution ("Third Party Programs"). Some of the Third Party Programs are available under open-source or free software licenses. The License Agreement accompanying the Licensed Software does not alter any rights or obligations you may have under those open-source or free software licenses. This document or appendix contains proprietary notices for the Third Party Programs and the licenses for the Third Party Programs, where applicable.
The following copyright statements and licenses apply to various open-source software components (or portions thereof) that are distributed with the Licensed Software.