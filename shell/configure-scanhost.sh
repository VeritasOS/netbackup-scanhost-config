#! /bin/bash

check=true
verbose=false

for flag in "$@"
do
    if [ $flag = '--install' ]; then
        check=false
    elif [ $flag = '--verbose' ]; then
        verbose=true
    else
        echo "Usage: ./configure-scanhost.sh [--install] [--verbose]";
        exit
   fi
done

# Check for existance of inputs.json
if [ ! -f "./inputs.json" ]; then
    echo "inputs.json not found in the current directory, exiting";
    exit;
fi

# Determine os
os=rhel
if  cat /etc/os-release | grep ^ID= | grep sled > /dev/null; then
    os='suse'
fi

# install jq if not present
if [ $os = 'suse' ]; then
    if ! zypper search --installed-only jq  >/dev/null 2>&1; then
        echo "Installing jq";
        zypper -n install jq > /dev/null 2>&1;
    fi
else
    if ! yum list installed jq  >/dev/null 2>&1; then
        echo "Installing jq";
        yum install jq -y > /dev/null 2>&1;
    fi
fi

install_avira=$(jq .install_avira inputs.json);

avira_package_path=$(jq .avira_package_path inputs.json);
if [ $avira_package_path = 'null' ] && [ $install_avira = true ]; then
    echo "Install avira is set to $install_avira and avira_package_path is not provided, exiting"
    exit
fi

# Removes last double quote character
# "/tmp/test.zip" -> "/tmp/test.zip
avira_package_path=${avira_package_path::-1};

# Removes first double quote character
# "/tmp/test.zip -> /tmp/test.zip
avira_package_path=${avira_package_path:1};

scan_user=$(jq .scan_user inputs.json);
if [ $scan_user = 'null' ]; then
    echo "scan_user not provided, exiting";
    exit;
fi

scan_user=${scan_user::-1};
scan_user=${scan_user:1};

scan_group=$(jq .scan_group inputs.json);
if [ $scan_group = 'null' ]; then
    echo "scan_group not provided, exiting";
    exit;
fi

scan_group=${scan_group::-1};
scan_group=${scan_group:1};

scan_user_password=$(jq .scan_user_password inputs.json);
if [ $scan_user_password = 'null' ]; then
    echo;
else
    scan_user_password=${scan_user_password::-1};
    scan_user_password=${scan_user_password:1};
fi

run_command() {
    if [ $verbose = true ]; then
        echo "Running command: $1";
    fi

    if [ $verbose = false ]; then
        $1 >> configure.log
    else
        $1 | tee configure.log
    fi
}

# Install packages
echo """ Following packages are required to run malware scan on the scan host
    1. libnsl
    2. nfs-utils/nfs-client
    3. cifs-utils
"""

# 1. Check for libnsl
libnsl_installed=false
if [ $os = 'suse' ]; then
    if zypper search --installed-only libnsl*  >/dev/null 2>&1; then
        libnsl_installed=true;
    fi
else
    if yum list installed libnsl*  >/dev/null 2>&1; then
        libnsl_installed=true;
    fi
fi

#2. Check for nfs-client.target service
nfs_client=false
STATUS="$(systemctl is-active nfs-client.target)"
if [ "${STATUS}" = "active" ]; then
   nfs_client=true
fi

#3. Check for smb.service
smb_client=false
if [ $os = 'suse' ]; then
    if zypper search --installed-only cifs-utils  >/dev/null 2>&1; then
        smb_client=true;
    fi
else
    if yum list installed cifs-utils >/dev/null 2>&1; then
        smb_client=true;
    fi
fi

echo "Minimum 8 CPUs and 32GB memory is recommanded";
echo "System has following configurations";
echo "No of CPU: $(lscpu | grep '^CPU(s):')";
echo "Memory details: $(lsmem -o size | grep online)";
echo;

if [ $libnsl_installed = true ]; then echo "libnsl exists"; else echo "libnsl does not exists"; fi
if [ $nfs_client = true ]; then echo "nfs-client is running"; else echo "nfs-client is not running"; fi
if [ $smb_client = true ]; then echo "smb-client is running"; else echo "smb-client is not running"; fi
echo;

if [ $check = false ]; then
    if [ $libnsl_installed = false ]; then
        echo "Installing libnsl";
        if [ $os = 'suse' ]; then
            run_command 'zypper -n install libnsl*';
        else
            run_command 'yum install libnsl* -y';
        fi
        echo "Installed libnsl";
        echo;
    fi

    if [ $nfs_client = false ]; then
        echo "Installing nfs-client";
        if [ $os = 'suse' ]; then
            run_command 'zypper -n install nfs-client';
        else
            run_command 'yum install nfs-utils* -y';
        fi
        run_command 'systemctl start nfs-client.target';
        run_command 'systemctl enable nfs-client.target';
        run_command 'systemctl status nfs-client.target';
        echo "Installed and started nfs-client service";
        echo;
    fi

    if [ $smb_client = false ]; then
        echo "Installing smb-client";
        if [ $os = 'suse' ]; then
            run_command 'zypper -n install cifs-utils';
        else
           run_command 'yum install cifs-utils -y';
        fi
        echo "Installed cifs-utils(samba client)";
        echo;
    fi
fi

# Create scan_group if not exists
if [ $(getent group $scan_group) ]; then
    echo "group $scan_group exists."
else
    if [ $check = false ]; then
        echo "creating group $scan_group"
        run_command "groupadd ${scan_group}";
    else
        echo "$scan_group does not exists"
    fi
fi

if [ $(getent passwd $scan_user) ]; then
    printf 'The user %s exists\n' "$scan_user"
    user_shell=$(getent passwd | grep $scan_user | cut -d":" -f 7 | grep bash);
    if [ -z "$user_shell" -a "$user_shell" == " " ]; then
        echo "default shell for $scan_user is not bash, exiting";
        exit
    fi

    if [ $check = true ]; then
        home_dir=$(eval echo ~$scan_user)
        bashrc_path="${home_dir}/.bashrc"

        str=$(grep NB_MALWARE_SCANNER_PATH $bashrc_path)

        existing_nb_malware_path=${str//"export NB_MALWARE_SCANNER_PATH="/ }

        if [ -z $existing_nb_malware_path ]; then
            echo "NetBackup Malware Scanner does not exists";
        else
            echo "NetBackup Malware Scanner exists at path: $existing_nb_malware_path";
        fi
        exit
    fi
else
    if [ $check = false ]; then
        printf 'Creating user %s \n' "$scan_user"
        run_command "useradd -s /bin/bash ${scan_user} -g ${scan_group} -m";
        if [ $scan_user_password = 'null' ]; then
            echo "Not Setting Password"
        else
            echo "Setting/Updating password for $scan_user";
            echo $scan_user:$scan_user_password | chpasswd
        fi
        echo "$scan_user ALL=(ALL) NOPASSWD:/bin/umount, /bin/mount" >> /etc/sudoers
    else
        echo "$scan_user does not exists"
        echo "NetBackup Malware scanner is not installed"
    fi
fi


if [ $check = true ]; then
    exit
fi

echo;
if [ $install_avira = true ]; then

    avira_base_package_name=(${avira_package_path//"/"/ })
    avira_base_package_name=${avira_base_package_name[-1]}

    avira_package_name_without_zip=(${avira_base_package_name//".zip"/ })
    avira_package_extract_location="/tmp/malware"

    # Create avira_package_extract_location
    mkdir -p $avira_package_extract_location
    chmod a+rwx $avira_package_extract_location

    # Extract NBAntimalware.zip to avira_package_extract_location
    run_command "unzip -o -d ${avira_package_extract_location} ${avira_package_path}";

    home_dir=$(eval echo ~$scan_user)
    bashrc_path="${home_dir}/.bashrc"

    str=$(grep NB_MALWARE_SCANNER_PATH $bashrc_path)

    existing_nb_malware_path=${str//"export NB_MALWARE_SCANNER_PATH="/ }

    avira_install_location=$home_dir/avira
    mkdir -p $avira_install_location

    if [ -z $existing_nb_malware_path ]; then
        echo "Starting fresh installation of NetBackup Malware Scanner";

        cmd="unzip -o -d $avira_install_location ${avira_package_extract_location}/${avira_package_name_without_zip}";
        if [ $os = 'rhel' ]; then
            cmd+='_LinuxR_x86/savapi-sdk-linux64.zip';
        else
            cmd+='_LinuxS_x86/savapi-sdk-linux64.zip';
        fi

        run_command "${cmd}"

        echo "export NB_MALWARE_SCANNER_PATH=${avira_install_location}/savapi-sdk-linux64/bin" >> $bashrc_path
        echo "export PATH=$PATH:${avira_install_location}/savapi-sdk-linux64/bin" >> $bashrc_path
        existing_nb_malware_path="${avira_install_location}/savapi-sdk-linux64/bin";
    else
        echo "Updating NetBackup Malware Scanner";

        cmd="unzip -o -d ${avira_package_extract_location} ${avira_package_extract_location}/${avira_package_name_without_zip}";

        if [ $os = 'rhel' ]; then
            cmd+='_LinuxR_x86/savapi-sdk-linux64.zip';
        else
            cmd+='_LinuxS_x86/savapi-sdk-linux64.zip';
        fi
        run_command "${cmd}"

        cp -r "${avira_package_extract_location}/savapi-sdk-linux64/bin/" $existing_nb_malware_path
        cd $existing_nb_malware_path
        mv bin/* .
        rm -rf bin
    fi

    echo "Updating virus information, this may take some time";
    cd $existing_nb_malware_path;
    run_command "update.sh";
    run_command "cd -";
    chown -R $scan_user:$scan_group $existing_nb_malware_path;
    echo "Updated virus information";

elif [ $check = false ]; then
    echo "Not installing NetBackup Malware Scanner as install_avira is set to false"

fi

if [ $check = false ]; then
    host_name=$(hostname);
    rsakey=$(ssh-keyscan $host_name  2>/dev/null | grep ssh-rsa | awk '{print $3}' | base64 -d | sha256sum);
    rsakey=${rsakey::-1};

    echo;
    echo "Use the following credentials (use value of scan_user_password for password)";
    echo "====================================================================";
    echo "hostname: $host_name";
    echo "username: $scan_user";
    echo "rsakey: $rsakey";
    echo "====================================================================";
fi