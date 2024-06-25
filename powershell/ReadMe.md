# Scan host configuration using PowerShell
    Version: 1.0

## Description
- NetBackup footprint is not required on the scan host.
- This utility installs and configures the prerequisites required to run a malware scan on the scan host (Windows Server 2016 and above).
- Additionally, this utility can be used to install `NetBackup Malware Scanner` on the scan host.
- The following would be installed/configured by the utility on the scan host
    * [OpenSSH-v9.4.0.0p1-Beta](https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip)
    * NFS-Client
    * [VC Runtime](https://aka.ms/vs/17/release/vc_redist.x64.exe)
    * Configurations: Non-administrator user creation

## Prerequisites
Ensure that the following prerequisites are present on the scan host
- Windows Server Version = 2016 and above
- Internet connectivity required

## Steps to configure scan host
1. Clone the repository from GitHub and move it to your scan host.
    * `git clone https://github.com/VeritasOS/netbackup-scanhost-config.git`
2. Open `powershell.exe` as Administrator. Traverse to `netbackup-scanhost-config\powershell`. (`cd netbackup-scanhost-config\powershell`)
3. Provide the required inputs in the `inputs.json` file. Refer `Terminologies` section for the complete list of inputs.
    * `install_avira`: Installs `NetBackup Malware Scanner` if set to `true`, defaults to `false`.
    * `avira_package_path`: (Required only if `install_avira` is set to `true`) Local absolute path to the `NetBackup Malware Scanner` zip package (NBAntimalwareClient) which is available on the Veritas download center.
4. Run the following command
    * `.\configure-scanhost.ps1 [--install] [--check] [--h/--help]`
5. Use credentials displayed at the end of the script to register the scan host to netbackup primary server.

## Terminologies
Below is the complete list of inputs that can be used in `inputs.json` file.

| Parameter name               |                                                       Default value                                                        | Description                                                                                                                        |
| -----------------------------|----------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| install_avira                | false                                                                                                                      | Installs `NetBackup Malware Scanner` if set to true                                                                                |
| avira_package_path           |                                                                                                                            | Local absolute path of the NetBackup Malware Scanner package                                                                       |
| scan_user                    | scanuser                                                                                                                   | The user will be created if it does not exist on the scan host and this user will be used for performing malware scan              |
| scan_group                   | scangroup                                                                                                                  | The group will be created if it does not exist on the scan host and scan scanuser will be added to this group                      |
| scan_user_password           |                                                                                                                            | Password is mandatory.                                         |
| openssh_download_url         | [OpenSSH-v9.4.0.0p1-Beta](https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.4.0.0p1-Beta/OpenSSH-Win64.zip) | URL from which the OPENSSH package would be installed                                                                              |
| vcruntime_download_url       | [VCRuntime](https://aka.ms/vs/17/release/vc_redist.x64.exe)                                                                | URL from which the VCRuntime package would be installed                                                                            |
| openssh_installation_path    | C:\OpenSSH                                                                                                                 | Path at which OPENSSH would be installed                                                                                           |
| avira_installation_path      | C:\Avira                                                                                                                   | Path at which NetBackup Malware Scanner would be installed                                                                         |
| scan_vm_backup               | false                                                                                                                      | Scan host should be used for scanning VMware/Cloud backup images (true = VMware/Cloud backup images, false = Others)               |

## Additional details
- Available flags
    1. --install  - This installs the prerequisites required to run the malware scan on the scan host.
    2. --check    - This will only check the prerequisites that are already present on the scan host.
    3. --h/--help - This will print the description of the utility along with the usage.
- The output of the installation can be found in the config.log file.
- If the user specified in inputs.json already exists on the host, the password for the user will be updated.
- If passwd/group file already exists, a backup copy of the file will be created and the current file will be overwritten. (e.g. passwd_04-12-2024-18.04.35.bak)
- A firewall rule will be added for allowing `sshd` service on port **22**

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