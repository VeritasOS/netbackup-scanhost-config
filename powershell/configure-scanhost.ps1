$ErrorActionPreference = "SilentlyContinue"
$check_configuration = 0

$greenCheck = @{
    Object = [Char]8730
    ForegroundColor = 'Green'
    NoNewLine = $true
}

$cross = @{
    Object = [Char]215
    ForegroundColor = 'Red'
    NoNewLine = $true
}

function PrintUsage {
    Write-Host "Usage: .\configure-scanhost.ps1 [--check] [--install] [--help/--h]"
}
function PrintDescription {
    Write-Host "`n"
    Write-Host "The following would be installed/configured by the utility on the scan host"
    Write-Host " - OpenSSH"
    Write-Host " - NFS-Client"
    Write-Host " - VC Runtime"
    Write-Host " - Configurations: Non-administrator user creation"
    Write-Host "`n"
}

function GetSystemSpecifications {
    $totalMemory = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1gb
    $totalProcessors = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

    if ($totalMemory -ge 32) {
        Write-Host @greenCheck
        Write-Host " Total Memory : $totalMemory GB" -ForegroundColor Green
    } else {
        Write-Host "! Total Memory : $totalMemory GB (Minimum recommended : 32 GB)" -ForegroundColor Yellow
    }

    if ($totalProcessors -ge 8) {
        Write-Host @greenCheck
        Write-Host " Total processors : $totalProcessors" -ForegroundColor Green
    } else {
        Write-Host "! Total processors : $totalProcessors (Minimum recommended : 8)" -ForegroundColor Yellow
    }
}

function CheckOperatingSystem {
    $operatingSystem = (Get-WmiObject -class Win32_OperatingSystem).Caption
    if (($operatingSystem -like "*2016*") -or ($operatingSystem -like "*2019*") -or ($operatingSystem -like "*2022*")) {
        Write-Host @greenCheck
        Write-Host " Operating system support [$operatingSystem]" -ForegroundColor Green
    } else {
        Write-Host @cross
        Write-Host " Operating system support [$operatingSystem]" -ForegroundColor Red
        if ($check_configuration -eq 0) {
            exit
        }
    }
}

function CheckFreeSpace {
    $freeSpace = [Math]::Round((Get-PSDrive ((Get-WmiObject Win32_OperatingSystem).SystemDrive).Replace(":","")).Free/1gb)
    if ($freeSpace -gt 10) {
        Write-Host @greenCheck
        Write-Host " Free disk space : $freeSpace GB" -ForegroundColor Green
    } else {
        Write-Host "! Free disk space : $freeSpace GB (Minimum recommended : > 10 GB)" -ForegroundColor Yellow
    }
}

function InstallOpenSSH {
    $sshdService = Get-Service -Name sshd
    if (-not ($null -eq $sshdService)) {
        $status = $sshdService.Status
        if ($status -eq "Stopped") {
            Start-Service -Name sshd | Out-File config.log
            if ($?) {
                $status = "Running"
            }
        }
        Write-Host @greenCheck
        Write-Host " OpenSSH [status:$status]" -ForegroundColor Green
    } elseif ($check_configuration -eq 1) {
        Write-Host @cross
        Write-Host " OpenSSH" -ForegroundColor Red
    } else {
        #----------------------------------------------------------INSTALL OPENSSH-----------------------------------------------#
        Write-Host "`nInstalling OpenSSH"
        $currentOpenSSH = Get-Command ssh.exe

        if ($currentOpenSSH) {
            $path = $currentOpenSSH.Source.Replace("\\", "\")
            $currentOpenSSHPath = $currentOpenSSH.Source.Replace("\ssh.exe", "")
            $oldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
            Add-Content config.log "Path variable before : $oldPath"
            $newPath = ($oldPath.Split(';') | Where-Object { -not ($_ -like "$currentOpenSSHPath*" ) }) -join ';'
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value "$newPath;"
        }

        $openssh_download_url = $inputs.openssh_download_url
        $openssh_installation_path = $inputs.openssh_installation_path
        if ($null -eq $openssh_installation_path) {
            $openssh_installation_path = "C:\OpenSSH"
        }

        if (-not (Test-Path -Path $openssh_installation_path)) {
            $openssh_installation_path = $openssh_installation_path.Replace("\\","\")
            New-Item -Path $openssh_installation_path -ItemType Directory | Out-File -Append config.log
            if (-not $?) {
                Write-Host "`nCould not create path $openssh_installation_path. Aborting OpenSSH installation ..." -ForegroundColor Red
                return
            }
        }

        Invoke-WebRequest $openssh_download_url -OutFile "$openssh_installation_path\OpenSSH64.zip"
        Expand-Archive "$openssh_installation_path\OpenSSH64.zip" -DestinationPath $openssh_installation_path -Force
        $openssh_installation_path = $openssh_installation_path + "\OpenSSH-Win64"
        $install_sshd_script = $openssh_installation_path + "\install-sshd.ps1"

        powershell.exe -ExecutionPolicy Bypass -File $install_sshd_script | Out-File -Append config.log
        if (-not $?) {
            Write-Host "`nError while installing OpenSSH [Failed - powershell.exe -ExecutionPolicy Bypass -File $install_sshd_script]" -ForegroundColor Red
            return
        }
        netsh advfirewall firewall add rule name=sshd dir=in action=allow protocol=TCP localport=22 | Out-File -Append config.log
        if (-not $?) {
            Write-Host "`nCould not add firewall rule for sshd service at port 22" -ForegroundColor Red
        }

        Set-Service -Name sshd -StartupType Automatic
        Start-Service -Name sshd

        $path = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path.Split(";")
        if (-not ($path -Contains $openssh_installation_path.Replace("\\" ,"\"))) {
            $path = $path -join ';'
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value "$path;$openssh_installation_path"
        }
        $path = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
        Add-Content config.log "Updated Path variable : $path"
        Write-Host "Installed OpenSSH successfully" -ForegroundColor Green
        $scan_user = $inputs.scan_user
        Write-Host "Try connecting to this host via SSH using $scan_user"
        #-------------------------------------------------------------------------------------------------------------------------#
    }
}

function ConfigureScanUser {
    #--------------------------------------------------CREATE SCANUSER--------------------------------------------------------#
    # Check for NFS-Client
    $nfsClient = Get-WindowsFeature -Name NFS-Client
    if (-not $nfsClient.Installed) {
        if ($check_configuration -eq 1) {
            Write-Host @cross
            Write-Host " NFS-Client" -ForegroundColor Red
        } else {
            Write-Host "`nInstalling NFS-Client"
            Install-WindowsFeature -Name NFS-Client | Out-File -Append config.log
            if (-not ($?)) {
                Write-Host "Error while installing NFS-Client`n" -ForegroundColor Red
            } else {
                Write-Host "Installed NFS-Client successfully`n" -ForegroundColor Green
            }
        }
    } else {
        Write-Host @greenCheck
        Write-Host " NFS-Client" -ForegroundColor Green
    }

    $scan_user = $inputs.scan_user
    $scan_group = $inputs.scan_group
    $scan_user_password = $inputs.scan_user_password
    $scan_vm_backup = $inputs.scan_vm_backup

    $scan_user_password = ConvertTo-SecureString $scan_user_password -AsPlainText -Force

    if (-not (Get-LocalUser -Name $scan_user)) {
        if ($check_configuration -eq 1) {
            Write-Host @cross
            Write-Host " Scan user [$scan_user]" -ForegroundColor Red
        } else {
            Write-Host "`Configuring scanuser"
            New-LocalUser -Name $scan_user -Description "scan_user" -Password $scan_user_password -PasswordNeverExpires | Out-File -Append config.log
            if ($?) {
                Write-Host "Created $scan_user successfully" -ForegroundColor Green
            } else {
                Write-Host "Error while creating local user $scan_user" -ForegroundColor Red
            }
        }
    } elseif ($check_configuration -eq 1) {
        Write-Host @greenCheck
        Write-Host " Scan user [$scan_user]" -ForegroundColor Green
    } else {
        # If user exists already, update the password
        $userAccount = Get-LocalUser -Name $scan_user
        $UserAccount | Set-LocalUser -Password $scan_user_password
        Write-Host @greenCheck
        Write-Host " Scan user [$scan_user] {Updated password successfully}" -ForegroundColor Green
    }

    if (-not (Get-LocalGroup -Name $scan_group)) {
        if ($check_configuration -eq 1) {
            Write-Host @cross
            Write-Host " Scan group [$scan_group]" -ForegroundColor Red
        } else {
            New-LocalGroup -Name $scan_group -Description "scan_group" | Out-File -Append config.log
            if ($?) {
                Write-Host "Created $scan_group successfully" -ForegroundColor Green
            } else {
                Write-Host "`nError while creating local group $scan_group" -ForegroundColor Red
            }
        }
    } else {
        Write-Host @greenCheck
        Write-Host " Scan group [$scan_group]" -ForegroundColor Green
    }

    # Check if user is a member of Administrators group
    $administrators = Get-LocalGroupMember -Name Administrators | Select-Object -ExpandProperty name
    if ($administrators -like "*\$scan_user") {
        Write-Host @greenCheck
        Write-Host " Scan user admin priviledges " -ForegroundColor Green
    } elseif ($check_configuration -eq 1) {
        Write-Host @cross
        Write-Host " Scan user admin priviledges" -ForegroundColor Red
    } else {
        net localgroup Administrators $scan_user /add > $null 2>&1
        if ($?) {
            Write-Host "Added $scan_user to Administrators successfully" -ForegroundColor Green
        } else {
            Write-Host "Error while adding $scan_user to Administrators" -ForegroundColor Red
        }
    }

    $scanGroupMembers = Get-LocalGroupMember -Name $scan_group | Select-Object -ExpandProperty name
    if (-not ($scanGroupMembers -like "*\$scan_user")) {
        if ($check_configuration -eq 1) {
            Write-Host @cross
            Write-Host " Scan user $scan_user is not a member of $scan_group" -ForegroundColor Yellow
        } else {
            net localgroup $scan_group $scan_user /add > $null 2>&1
            if ($?) {
                Write-Host "Added $scan_user to $scan_group successfully" -ForegroundColor Green
            } else {
                Write-Host "Error while adding $scan_user to $scan_group" -ForegroundColor Yellow
            }
        }
    }

    if ($check_configuration -eq 0) {
        $identityMappingFilePath = (Get-ChildItem -Path Env:\SystemRoot).Value + "\System32\drivers\etc\passwd"
        $groupMappingFilePath = (Get-ChildItem -Path Env:\SystemRoot).Value + "\System32\drivers\etc\group"

        if (-not (Test-Path -Path $identityMappingFilePath)) {
            New-Item -Path $identityMappingFilePath -ItemType File | Out-File -Append config.log
            if ($?) {
                Write-Host "Created identity mapping file [$identityMappingFilePath] successfully" -ForegroundColor Green
            } else {
                Write-Host "Could not create path identity mapping file [$identityMappingFilePath]" -ForegroundColor Red
                return
            }

        } else {
            # Create a backup copy of current passwd file
            $timestamp = Get-Date -Format "MM-dd-yyyy-HH.mm.ss"
            $backup_file = $identityMappingFilePath + "_" + $timestamp + ".bak"
            Copy-Item -Path $identityMappingFilePath -Destination $backup_file
        }

        if (-not (Test-Path -Path $groupMappingFilePath)) {
            New-Item -Path $groupMappingFilePath -ItemType File | Out-File -Append config.log
            if ($?) {
                Write-Host "Created group mapping file [$groupMappingFilePath] successfully" -ForegroundColor Green
            } else {
                Write-Host "Could not create group mapping file [$groupMappingFilePath]" -ForegroundColor Yellow
            }
        } else {
            # Create a backup copy of current group file
            $timestamp = Get-Date -Format "MM-dd-yyyy-HH.mm.ss"
            $backup_file = $groupMappingFilePath + "_" + $timestamp + ".bak"
            Copy-Item -Path $groupMappingFilePath -Destination $backup_file
        }

        $uidMapping = "$scan_user`:x`:0`:0`:Description`:C`:\Users\$scan_user"
        if ($scan_vm_backup -eq "true") {
            $uidMapping = "$scan_user`:x`:0`:0`:Description`:C`:\Users\$scan_user"
        } else {
            $uidMapping = "$scan_user`:x`:1000`:1000`:Description`:C`:\Users\$scan_user"
        }
        $groupMapping = "$scan_group`:x:0:0"
    }

    if ($check_configuration -eq 0) {
        if (-not (Get-NfsMappingStore).UNMLookupEnabled) {
            Set-NfsMappingStore -EnableUNMLookup $True -UNMServer localhost
        }

        Set-Content -Path $identityMappingFilePath -Value $uidMapping
        Set-Content -Path $groupMappingFilePath -Value $groupMapping
        Write-Host "`nRestarting NFS-Client Service`n"
        nfsadmin client stop
        nfsadmin client start
    }

    # Verify the UID mapping
    if (Get-LocalUser -Name $scan_user) {
        $userMapping = Get-NfsMappedIdentity -AccountName $inputs.scan_user -AccountType User
        if ($?) {
            if ($check_configuration -eq 0) {
                Write-Host "`nScan user [$scan_user] mapped successfully" -ForegroundColor Green
            } else {
                Write-Host @greenCheck
                $userIdentifier = $userMapping.UserIdentifier
                Write-Host " scan user nfs identity mapping [$scan_user`:$userIdentifier]" -ForegroundColor Green
            }
        } else {
            if ($check_configuration -eq 0) {
                Write-Host "`nCould not get nfs identity mapping for $scan_user" -ForegroundColor Red
            } else {
                Write-Host @cross
                $userIdentifier = $userMapping.UserIdentifier
                Write-Host " scan user nfs identity mapping"
            }
        }
    }
    #------------------------------------------------------------------------------------------------------------------------#
}

function InstallVCRuntime {
    $currentVCRuntime = Get-Package -Name "Microsoft Visual C++ 2022 X64*"
    if ($currentVCRuntime) {
        Write-Host @greenCheck
        Write-Host " VCRuntime" -ForegroundColor Green
    } elseif ($check_configuration -eq 1) {
        Write-Host @cross
        Write-Host " VCRuntime" -ForegroundColor Red
    } else {
        #------------------------------------------------INSTALL VCRUNTIMME------------------------------------------------------#
        Write-Host "`nInstalling VCRuntime"
        $vcRuntimeURL = $inputs.vcruntime_download_url
        Invoke-WebRequest $vcRuntimeURL -OutFile .\vcredist_x86.exe
        Start-Process -Wait -FilePath .\vcredist_x86.exe -Argument "/silent" -PassThru | Out-File -Append config.log
        if (-not $?) {
            Write-Host "Could not install VCRuntime" -ForegroundColor Red
        } else {
            Write-Host "Installed VCRuntime successfully" -ForegroundColor Green
        }
        Remove-Item -Path .\vcredist_x86.exe -Force
        #------------------------------------------------------------------------------------------------------------------------#
    }
}

function InstallAviraTool {
    $avira_path = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name NB_MALWARE_SCANNER_PATH).NB_MALWARE_SCANNER_PATH
    if ($check_configuration -eq 1) {
        $exitCode = -1
        if (-not ($null -eq $avira_path)) {
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = "$avira_path\avira_lib_dir_scan.exe"
            $pinfo.RedirectStandardError = $true
            $pinfo.RedirectStandardOutput = $true
            $pinfo.UseShellExecute = $false
            $pinfo.Arguments = "-v"
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $pinfo
            $p.Start() | Out-Null
            $stdout = $p.StandardOutput.ReadToEnd().Replace("`n","")
            $p.WaitForExit()
            $exitCode = $p.ExitCode
            if ($exitCode -eq 0) {
                Write-Host @greenCheck
                Write-Host " NetBackup-Malware-Scanner | $stdout" -ForegroundColor Green
            } else {
                Write-Host "! Error while checking NetBackup-Malware-Scanner version" -ForegroundColor Yellow
            }
        } else {
            Write-Host @cross
            Write-Host " NetBackup-Malware-Scanner" -ForegroundColor Red
        }
    } else {
        #---------------------------------------------------INSTALL AVIRA--------------------------------------------------------#
        Write-Host "`nInstalling NetBackup-Malware-Scanner"
        $avira_package_path = $inputs.avira_package_path
        $avira_installation_path = $inputs.avira_installation_path

        if (-not ($null -eq $avira_package_path)) {
            $avira_package_path = $avira_package_path.Replace("\\", "\")
        }
        if ($null -eq $avira_installation_path) {
            $avira_installation_path = "C:\Avira"
        } else {
            $avira_installation_path = $avira_installation_path.Replace("\\", "\")
        }
        if (Test-Path -Path $avira_package_path) {
            if (-not (Test-Path -Path $avira_installation_path)) {
                New-Item -Path $avira_installation_path -ItemType Directory | Out-File -Append config.log
                if (-not $?) {
                    Write-Host "`Could not create path $avira_installation_path. Aborting NetBackup-Malware-Scanner installation ..." -ForegroundColor Red
                    return
                }
            }
            Expand-Archive $avira_package_path -DestinationPath $avira_installation_path -Force
            Copy-Item -Path "$avira_installation_path\NBAntiMalwareClient_2.4_AMD64\*" -Destination $avira_installation_path -Recurse
            Expand-Archive "$avira_installation_path\savapi-sdk-win64.zip" -DestinationPath "$avira_installation_path\savapi-sdk-win64" -Force
            if (-not ($null -eq $avira_path)) {
                Write-Host "NetBackup-Malware-Scanner installed successfully at $avira_path" -ForegroundColor Green
                Move-Item -Path "$avira_installation_path\savapi-sdk-win64\bin\*" -Destination $avira_path -Force
                Remove-Item -Path "$avira_installation_path\NBAntiMalwareClient_2.4*" -Recurse
                Write-Host "Updating NetBackup-Malware-Scanner ..."
                $currentLocation = $pwd.Path
                Set-Location -Path $avira_path
                .\update.bat | Out-File config.log
                if ($?) {
                    Write-Host "NetBackup-Malware-Scanner updated successfully`n" -ForegroundColor Green
                } else {
                    Write-Host "Could not update NetBackup-Malware-Scanner`n" -ForegroundColor Yellow
                }
                Set-Location $currentLocation
                return
            }
            Remove-Item -Path "$avira_installation_path\NBAntiMalwareClient_2.4*" -Recurse
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name NB_MALWARE_SCANNER_PATH -Value "$avira_installation_path\savapi-sdk-win64\bin"
            Write-Host "NetBackup-Malware-Scanner installed successfully at $avira_installation_path" -ForegroundColor Green
            Write-Host "Updating NetBackup-Malware-Scanner ..."
            $currentLocation = $pwd.Path
            Set-Location -Path "$avira_installation_path\savapi-sdk-win64\bin\"
            .\update.bat | Out-File config.log
            if ($?) {
                Write-Host "NetBackup-Malware-Scanner updated successfully`n" -ForegroundColor Green
            } else {
                Write-Host "Could not update NetBackup-Malware-Scanner`n" -ForegroundColor Yellow
            }
            Set-Location $currentLocation
        } else {
            Write-Host "$avira_package_path does not exist" -ForegroundColor Red
        }
        #------------------------------------------------------------------------------------------------------------------------#
    }
}

function UseUnicodeUTF8 {
    $ACP =  (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage' -Name "ACP").ACP
    $OEMCP = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage' -Name "OEMCP").OEMCP
    $MACCP = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage' -Name "MACCP").MACCP
    if ((65001 -eq $ACP) -and (65001 -eq $OEMCP) -and (65001 -eq $MACCP)) {
        Write-Host @greenCheck
        Write-Host " Use unicode UTF-8 for worldwide language support" -ForegroundColor Green

    } elseif ($check_configuration -eq 1) {
        Write-Host @cross
        Write-Host " Use unicode UTF-8 for worldwide language support" -ForegroundColor Red

    } else {
        Write-Host "`nEnabling UTF-8 encoding for worldwide language support"
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage' -Name "ACP" -Value "65001"
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage' -Name "OEMCP" -Value "65001"
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Nls\CodePage' -Name "MACCP" -Value "65001"
        Write-Host "Enabled - Use unicode UTF-8 for worldwide language support" -ForegroundColor Green
        Write-Host "Restart is required for this change to take effect`n" -ForegroundColor Yellow
    }
}

function GetConnectionDetails {
    $userName = $inputs.scan_user
    $openssh_installation_path = $inputs.openssh_installation_path
    if ($null -eq $openssh_installation_path) {
        $openssh_installation_path = "C:\OpenSSH"
    }

    $ssh_keyscan = (Get-Command ssh-keyscan.exe).Source
    if ($null -eq $ssh_keyscan) {
        $ssh_keyscan = "$openssh_installation_path\OpenSSH-Win64\ssh-keyscan.exe"
    }
    $ipv4Address = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
    $rsa_key = & $ssh_keyscan $ipv4Address 2>$null
    $rsa_key = (Write-Output $rsa_key | findstr ssh-rsa).Split(" ")[2]
    $bytes = [System.Convert]::FromBase64String($rsa_key)
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash($bytes)
    $hashString = [System.BitConverter]::ToString($hash)
    $rsa_fingerprint = $hashString.Replace('-', '').ToLower()

    Write-Host "Use the following credentials (use value of scan_user_password for password)"
    Write-Host "==============================================================================="
    Write-Host "Hostname : $ipv4Address"
    Write-Host "Username : $userName"
    Write-Host "Rsa-Key  : $rsa_fingerprint"
    Write-Host "==============================================================================="
}

if (-not ($args.Length -eq 1)) {
    PrintUsage
    exit
}
if (-not ($args.Contains("--check") -or $args.Contains("--install") -or $args.Contains("--help") -or $args.Contains("--h"))) {
    PrintUsage
    exit
}

if ($args[0] -eq "--check") {
    $check_configuration = 1
} elseif (($args[0] -eq "--help") -or ($args[0] -eq "--h")) {
    PrintDescription
    PrintUsage
    exit
}

if (-not (Test-Path -Path inputs.json)) {
    Write-Host "Input file [inputs.json] does not exist" -ForegroundColor Red
    exit
}

# Validate input JSON
$valid = try { $inputs = Get-Content .\inputs.json -Raw | ConvertFrom-Json; $true } catch { $false }

if (-not $valid) {
    Write-Host "Input JSON is invalid" -ForegroundColor Red
    exit
}

# Check for mandatory inputs
if (($null -eq $inputs.scan_user) -or ($null -eq $inputs.scan_group) -or ($null -eq $inputs.scan_user_password) -or ($null -eq $inputs.scan_vm_backup) -or ($null -eq $inputs.vcruntime_download_url) -or ($null -eq $inputs.openssh_download_url) -or ($null -eq $inputs.install_avira) -and ($check_configuration -eq 0)) {
    Write-Host "`nProvide the mandatory parameters in inputs.json - scan_user, scan_group, scan_user_password, scan_vm_backup, vcruntime_download_url, openssh_download_url, install_avira"
    exit
}

if ($inputs.install_avira -eq "true") {
    if (($null -eq $inputs.avira_package_path) -or -not (Test-Path -Path $inputs.avira_package_path)) {
        Write-Host "avira_package_path does not exist" -ForegroundColor Red
        exit
    }
}

# SSL/TLS Secure Channel (Protocols needed for windows server 2016)
if ((Get-WmiObject -class Win32_OperatingSystem).Caption -like "*2016*") {
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
}

PrintDescription
CheckOperatingSystem
GetSystemSpecifications
CheckFreeSpace
ConfigureScanUser
InstallOpenSSH
InstallVCRuntime
InstallAviraTool
if ($inputs.install_avira -eq "false" -and $check_configuration -eq 0) {
    Write-Host "! Not installing NetBackup Malware Scanner as install_avira is set to false" -ForegroundColor Yellow
}
UseUnicodeUTF8

if (Get-LocalUser -Name $inputs.scan_user) {
    $userId = (Get-NfsMappedIdentity -AccountName $inputs.scan_user -AccountType User).UserIdentifier
    if (-Not ($null -eq $userId)) {
        if ($userId -eq 0) {
            Write-Host "- Scan host is configured for scanning VM-backup images`n"
        } else {
            Write-Host "- Scan host is configured for scanning non VM-backup images`n"
        }
    }
}

if ($check_configuration -eq 0) {
    GetConnectionDetails
}