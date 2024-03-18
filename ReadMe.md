# Scan host configuration

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

### Following are the ways to configure the scan hosts

| Script     | Supported scan host platforms |
| -----------| ------------------- |
| Ansible    | Linux, Windows      |
| Shell      | Linux               |
| Powershell | Windows             |

---
**NOTE**
Refer following `ReadMe`(s) for further details
1. ansible/ReadMe.md
2. shell/ReadMe.md
3. powershell/ReadMe.md
---

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