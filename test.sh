#!/bin/bash

# This script for Custom SSHD config per CIS Hardening

set -e

######################################################################################################
# Control ID's
sudo echo "
#Custom SSHD config per CIS Hardening
Banner /etc/issue.net
HostbasedAuthentication no
MaxStartups 10:30:60
ClientAliveCountMax 3
LogLevel INFO
MaxSessions 1
IgnoreRhosts yes
UsePAM YES
PermitUserEnvironment no
ClientAliveInterval 300
MaxAuthTries 3
LoginGraceTime 60
PermitEmptyPasswords no
" | sudo tee -a /etc/ssh/sshd_config

## Custom /etc/bashrc config per CIS Hardening
sudo echo "
#Custom /etc/bashrc config per CIS Hardening
# Control ID 2678,29216
TMOUT=600
umask 0027
" | sudo tee -a /etc/bashrc

## Custom /etc/chrony.conf config per CIS Hardening
sudo echo "
#Custom /etc/chrony.conf config per CIS Hardening
# Control ID 13138
pool pool.ntp.org iburst maxsources 3
" | sudo tee -a /etc/chrony.conf

## Custom /etc/login.defs config per CIS Hardening
sudo echo "
#Custom /etc/login.defs config per CIS Hardening
# Control ID 1072,11401,1073
umask 0027
PASS_MIN_DAYS 12
PASS_MAX_DAYS 60
" | sudo tee -a /etc/login.defs

## Custom /etc/pam.d/su config per CIS Hardening
sudo echo "
#Custom /etc/pam.d/su config per CIS Hardening
# Control ID 6796
auth required pam_wheel.so
" | sudo tee -a /etc/pam.d/su

## Custom /etc/profile config per CIS Hardening
sudo echo "
# Custom /etc/profile config per CIS Hardening
# Control ID 2679,3371
TMOUT=600
umask 0027
" | sudo tee -a /etc/profile

## Custom /etc/sudoers config per CIS Hardening
sudo echo "
# Custom /etc/sudoers config per CIS Hardening
# Control ID 17145,17126,29158
Defaults logfile= /var/log/sudo.log
Defaults use_pty
Defaults timestamp_timeout=900
" | sudo tee -a /etc/sudoers

## Custom /etc/sudoers.d/google_sudoers config per CIS Hardening
sudo echo "
# Custom /etc/sudoers.d/google_sudoers config per CIS Hardening
# Control ID 17145,17126
Defaults logfile= /var/log/sudo.log
Defaults use_pty
" | sudo tee -a /etc/sudoers.d/google_sudoers

## Custom /etc/security/pwquality.conf config per CIS Hardening
sudo echo "
# Control ID 17690,17691,17692,17693,17292
dcredit = 1
lcredit = 1
ocredit = 1
ucredit = 1
minclass = 4
minlen = 14
# Control ID 17694
difok = 8
# Control ID 27203
enforce_for_root
# Control ID 28581,29535
maxrepeat = 3
# Control ID 29535
maxsequence = 3
" | sudo tee -a /etc/security/pwquality.conf

## Custom /etc/security/pwquality.conf.d/*.conf config per CIS Hardening
sudo touch /etc/security/pwquality.conf.d/pwquality.conf
sudo echo "
# Custom /etc/security/pwquality.conf.d/*.conf config per CIS Hardening
# Control ID 17690,17691,17692,17693,17292
dcredit = 1
lcredit = 1
ocredit = 1
ucredit = 1
minclass = 4
minlen = 14
# Control ID 17694
difok = 8
# Control ID 27203,
enforce_for_root
# Control ID 28581,29535
maxrepeat = 3
# Control ID 29535
maxsequence = 3
" | sudo tee -a /etc/security/pwquality.conf.d/*.conf

## Custom /etc/rsyslog.conf config per CIS Hardening
sudo echo "
# Custom /etc/rsyslog.conf config per CIS Hardening
# Control ID 10666
FileCreateMode= 0644
" | sudo tee -a /etc/rsyslog.conf

#Custom	/etc/sysconfig/chronyd config per CIS Hardening
sudo echo '
# Control ID 10664
OPTIONS="-u chrony"
' | sudo tee -a /etc/sysconfig/chronyd

#10507	/etc/sysctl.conf config per CIS Hardening
sudo echo '
# Control ID 10507
kernel.randomize_va_space = 2
# Control ID 5957
net.ipv4.conf.all.secure_redirects = 0
# Control ID 5961
net.ipv4.conf.default.secure_redirects = 0
# Control ID 5958
net.ipv4.conf.default.rp_filter=1
# Control ID 28688
net.ipv6.conf.all.forwarding = 0
' | sudo tee -a /etc/sysctl.conf

# 20570, 20572 /etc/security/faillock.conf config per CIS Hardening
sudo echo '
# Control ID 20570
deny=3
# Control ID 20572
unlock_time = 900
' | sudo tee -a /etc/security/faillock.conf

# 28688 config /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf per CIS Hardening
echo '
# Control ID 28688
net.ipv6.conf.all.forwarding = 0
' | sudo tee -a /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf

# 29042 /etc/fstab per CIS Hardening
echo '
# Control ID 29042
tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
' | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount -o remount /dev/shm

# 29449	/etc/security/pwhistory.conf per CIS Hardening
echo '
# Control ID 29449
remember = 10
# Control ID 29450
enforce_for_root
' | sudo tee -a /etc/security/pwhistory.conf

# Control ID 10684, 4750
echo '
######################################
***"Warnig: Authorized Users Only"***
######################################
' | sudo tee -a /etc/issue.net /etc/issue
sudo sed -i 's/\\S//' /etc/issue.net /etc/issue && sudo sed -i 's/Kernel \\r on an \\m//' /etc/issue.net /etc/issue
 
##############################################################################################################################
## Directory, Files Custom Permissions 

#7339	/etc/cron.d/	
sudo chmod 600 /etc/cron.d/
#7341	/etc/cron.daily/	
sudo chmod 600 /etc/cron.daily/
#5154	/etc/crontab	
sudo chmod 600 /etc/crontab
#7345	/etc/cron.weekly/	
sudo chmod 600 /etc/cron.weekly/
#7347	/etc/cron.monthly/	
sudo chmod 600 /etc/cron.monthly/
#7343	/etc/cron.hourly/	
sudo chmod 600 /etc/cron.hourly/
#5796	/etc/cron.deny	
sudo chmod 600 /etc/cron.deny
#4772, 5140	/etc/at.allow
sudo touch /etc/at.allow && sudo chmod 600 /etc/at.allow && sudo chown root:root /etc/at.allow
#5057 /etc/cron.allow
sudo touch /etc/cron.allow && sudo chmod 600 /etc/cron.allow
# 27274
sudo chmod 600 /var/log/sssd
#
sudo chmod u-x,og-rwx /etc/ssh/sshd_config && sudo chown root:root /etc/ssh/sshd_config
#11705	/etc/ssh/ssh_host*key
sudo chmod 0640 /etc/ssh/ssh_host*key

# Uncommenting the values
sudo sed -i 's/^#Storage=auto/Storage=persistent/' /etc/systemd/journald.conf
sudo sed -i 's/^#Compress=yes/Compress=yes/' /etc/systemd/journald.conf
sudo sed -i 's/^#ForwardToSyslog=no/ForwardToSyslog=yes/' /etc/systemd/journald.conf #29284
sudo sed -i 's/^kernel.yama.ptrace_scope = 0/kernel.yama.ptrace_scope = 1 # Hardening Policy Control ID 28632/' /usr/lib/sysctl.d/10-default-yama-scope.conf
sudo sed -i 's/^kernel.yama.ptrace_scope = 0/kernel.yama.ptrace_scope = 1 # Hardening Policy Control ID 28632/' /lib/sysctl.d/10-default-yama-scope.conf
sudo sed -i 's/^net.ipv4.conf.default.rp_filter = 2/net.ipv4.conf.default.rp_filter = 0 # Hardening Policy Control ID 28986/' /usr/lib/sysctl.d/50-default.conf
sudo sed -i 's/^net.ipv4.conf.default.rp_filter = 2/net.ipv4.conf.default.rp_filter = 0 # Hardening Policy Control ID 28986/' /lib/sysctl.d/50-default.conf
sudo sed -i 's/^net.ipv4.conf.default.rp_filter = 1/net.ipv4.conf.default.rp_filter = 0 # Hardening Policy Control ID 28986/' /usr/lib/sysctl.d/50-redhat.conf
sudo sed -i 's/^net.ipv4.conf.default.rp_filter = 1/net.ipv4.conf.default.rp_filter = 0 # Hardening Policy Control ID 28986/' /lib/sysctl.d/50-redhat.conf
sudo sed -i 's/^net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.default.rp_filter = 0 # Hardening Policy Control ID 28986/' /etc/sysctl.d/60-gce-network-security.conf
sudo sed -i 's/^net.ipv4.conf.all.secure_redirects=1/net.ipv4.conf.all.secure_redirects = 0 # Hardening Policy Control ID 29230/' /etc/sysctl.d/60-gce-network-security.conf
sudo sed -i 's/^net.ipv4.conf.default.secure_redirects=1/net.ipv4.conf.default.secure_redirects = 0 # Hardening Policy Control ID 29231/' /etc/sysctl.d/60-gce-network-security.conf
sudo sed -i 's/^ProcessSizeMax=1G/ProcessSizeMax=0 # Hardening Policy Control ID 29027/' /etc/systemd/coredump.conf
sudo sed -i 's/^UMASK/#UMASK/' /etc/login.defs # Hardening Policy Control ID 29216

sudo sed -i 's/^#Storage=external/Storage=none # Hardening Policy Control ID 17222/' /etc/systemd/coredump.conf

# update in  /etc/sysctl.conf below lines
# 7505,5961,5957,5958
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv6.conf.all.accept_ra=0
sudo sysctl -w net.ipv6.conf.default.accept_ra=0
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
# 17128
sudo systemctl --now mask nftables

# 20632
sudo sysctl -w kernel.yama.ptrace_scope=1

#29387 Run the following command to install rsyslog:
sudo dnf install -y rsyslog

# Control ID 22686, 10860
sudo echo '
# Control ID 22686, 10860
tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0
' | sudo tee -a /etc/fstab
sudo systemctl daemon-reload && sudo mount /tmp && sudo systemctl daemon-reload

#29444
sudo dnf install systemd-journal-remote -y && sudo systemctl unmask systemd-journal-upload.service && sudo systemctl --now enable systemd-journal-upload.service
#&& sudo systemctl restart systemd-journal-upload.service

# remove old kernel packages
sudo dnf list installed kernel*
sudo dnf remove --oldinstallonly --setopt installonly_limit=2 kernel -y
echo "Finished cleanup old kernerls"
sudo dnf list installed kernel*

# Restart Services,
echo 'Restart Services'
#sudo systemctl restart sshd.service
sudo systemctl restart chronyd
sudo systemctl restart rsyslog
#&& sudo systemctl restart systemd-journal-upload.service
sudo systemctl daemon-reload
#echo 'Checking sshd service Status'
#sudo systemctl status sshd.service && journalctl -xeu sshd.service


echo 'Completed rhel9-cis-hardening.sh Successfully'

######y
name: RHEL Packer
# Only triggers the GHA ifa push happened to the main branch and to the path images/rhel
on:
  push:
    branches:
      - main
    paths:
      - 'images/RHEL/**'
  workflow_dispatch:
    inputs:
      var-file-prefix:
        description: 'Prefix for the variable file'
        required: true
        type: choice
        default: 'Dev'
        options:
          - 'Dev'
          - 'Stage'
          - 'Prod'
      build-template:
        description: 'Build template'
        required: true
        type: string
        default: 'prime_rhel.pkr.hcl'


permissions:
  contents: read
  id-token: write

jobs:
  packer:
    name: 'RHEL Packer'
    runs-on: [docker]
# the above line instructing GHA to run on a self-hosted runner with a label packer-poc
    
#This step will clone the repo temporarily into the runner VM    
    steps:

    - name: Checkout
      uses: actions/checkout@v4
      
    - name: Authenticate to Google Cloud (Keyless)
      uses: 'google-github-actions/auth@v2'
      with:
        workload_identity_provider: projects/584369730819/locations/global/workloadIdentityPools/github-pool/providers/github-identity-provider
        service_account: svc-nonprod-github-cicd@prj-ss-prod-devops-0f8c.iam.gserviceaccount.com
        access_token_lifetime: 300s

    - name: Setup Gcloud
      uses: google-github-actions/setup-gcloud@v2
      
    - name: Setup `packer`
      uses: hashicorp/setup-packer@v3
      id: setup
      with:
        version: ${{ env.PRODUCT_VERSION }}

    - name: Install plugins
      run: "packer plugins install github.com/hashicorp/googlecompute"

    - name: Run `packer init`
      id: init
      run: "packer init ${{ inputs.build-template || 'prime_rhel.pkr.hcl' }}"

    - name: Run `packer validate`
      # continue-on-error: true
      id: validate
      run: "packer validate -var-file=images/RHEL/${{ inputs.var-file-prefix || 'Dev' }}.pkrvars.json ${{ inputs.build-template || 'prime_rhel.pkr.hcl' }}"

    - name: Run Packer
      run: "packer build -var-file=images/RHEL/${{ inputs.var-file-prefix || 'Dev' }}.pkrvars.json ${{ inputs.build-template || 'prime_rhel.pkr.hcl' }}"
      env: 
        PKR_VAR_qualys_agent_activation_id: ${{ secrets.QUALYS_AGENT_ACTIVATION_ID }}
        PKR_VAR_qualys_agent_customer_id: ${{ secrets.QUALYS_AGENT_CUSTOMER_ID }}
        PKR_VAR_qualys_agent_server_uri: ${{ secrets.QUALYS_AGENT_SERVER_URI }}
        PKR_VAR_sentinelone_agent_token: ${{ secrets.SENTINELONE_AGENT_TOKEN}}
        PKR_VAR_dynatrace_reg_token: ${{ secrets.DYNATRACE_REG_TOKEN }}
    
    - name: Create a Validation VM
      run: |
          echo "Executing VM Creation Script..."
          chmod +x ./scripts/create_validation_vm.sh
          ./scripts/create_validation_vm.sh
      env:
        SSH_PUBLIC_KEY_STRING: ${{ secrets.POC_SSH_PUBLIC_KEY }}
