# Scan host configuration using shell
    Version: 1.0

## Description
- NetBackup footprint is not required on the scan host.
- This utility installs and configures the prerequisites required to run a malware scan on the scan host (RHEL (8.x, 9.x) / SUSE 12 and above).
- Additionally, this utility can be used to install `NetBackup Malware Scanner` on the scan host.
- The following will be installed/configured by the utility on the scan hosts.
    *  NFS client
    *  SMB client
    * Configuration: Non-root user creation
- By default, this script runs as a checker and verifies all the things required for a malware scan to run. To install all the prerequisites use `--install` flag.

## Prerequisites
Ensure that the following prerequisites are present on the scan host.
- RHEL Version = 8.x, 9.x
- Subscription manager attached
- Internet connectivity required
- Uses `jq` for parsing the `inputs.json` file
- Default login shell should be `bash`

## Steps to configure scan host
1. Clone the repository from GitHub and move it to your scan host.
    * `git clone https://github.com/VeritasOS/netbackup-scanhost-config.git`
2. Traverse to `netbackup-scanhost-config\shell`. (`cd netbackup-scanhost-config\shell`)
3. Provide the required inputs in the `inputs.json` file. Refer `Terminologies` section for the complete list of inputs.
    * `install_avira`: Installs `NetBackup Malware Scanner` if set to `true`, defaults to `false`.
    * `avira_package_path`: (Required only if `install_avira` is set to `true`) Local absolute path to the `NetBackup Malware Scanner` zip package (NBAntimalwareClient) which is available on the Veritas download center.
4. Run the following command.
    * `sh configure-scanhost.sh [--verbose] [--install]`
5. Use credentials displayed at the end of the script to register the scan host to netbackup primary server.

## Terminologies
Below is the complete list of inputs that can be used in `inputs.json` file.

| Parameter name      | Default value                           | Description                                                                                                                          |
| --------------------|-----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| install_avira       | false                                   | Installs `NetBackup Malware Scanner` if set to `true`                                                                                |
| avira_package_path  |                                         | Local absolute path of the `NetBackup Malware Scanner` package                                                                       |
| scan_user           | scanuser                                | The user will be created if it does not exist on the scan host and `NetBackup Malware Scanner` will be configured using the same user|
| scan_group          | scangroup                               | This group would be created on the requested host if it does not exist and `scan_user` will be added in the same group               |
| scan_user_password  |                                         | This would be the password for `scan_user`, if not provided then password would not be set                                           |

## Additional details
- Available flags
    1. --install - This installs the prerequisites required to run the malware scan on the scan host.
    2. --verbose - This will print the actual command execution, and increase output (can be used for debugging if needed).

- The output of the installation can be found in the config.log file.
- If the user specified in `inputs.json` already exists on the host, the password for the user will be updated.
- If **any package** is not installed, contact the operating system provider to add respective repositories and then run the script again or install the package manually.

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