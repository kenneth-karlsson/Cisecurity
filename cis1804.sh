#! /bin/bash

# Check for bash
case ${BASH} in
    '') echo "This script must be executed with bash."
       exit 1 ;;
esac

################################### HARDENING SCRIPT FOR UBUNTU 18.04 ########################### 
VERSION=20201217-draft

[[ ${USER} != root ]] && echo -e "\n\nPlease execute with sudo or as root.\n" && exit 1

(echo $@ | grep -qi "\-v") && echo -e "Version: ${VERSION}" &&  exit

(echo $@ | grep -qi "\-l") && echo -e "https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode" && exit

(echo $@ | grep -qi "\-d") && echo -e "
DISCLAIMER:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE." && exit

(echo $@ | grep -qi -E "\-h|--help") && echo -e "
Usage: sudo $0

-h  (Show help)
-v  (Show version)
-l  (Show license)
-d  (Show disclaimer)
-u  (Update mode. Harden Linux)
-q  (Quite mode)
-b  (Show Benchmark header details)
-s1 (Server level 1)
-s2 (Server level 2)
-w1 (Worksation level 1)
-w2 (Worksation level 2)

The purpose of this script is to harden Ubuntu Linux systems.
It is based on CIS Ubuntu Linux 18.04 LTS Benchmark v2.1.0 from www.cisecurity.org
https://www.cisecurity.org/cis-securesuite/cis-securesuite-membership-terms-of-use/
It has only been tested on Ubuntu 1804 X64.

Executing this script without update mode will not make any changes to the operating system.
It will however indicate what would be done if run in update mode.

DO NOT EXECUTE SCRIPT ON PRODUCTION SERVERS IN UPDATE MODE.
Update mode will make extensive changes to the operating system.
This could render the server unusable or inaccessable.
It could also uninstall a number of packages. Make sure you adjust this list in .cisrc.
The .cisrc file is created when executing script for the first time.
If you are logged in as root, make sure you can still log in after executing in update mode before logging out.

To disable individual benchmarks set variable W and S to 3.
To exit before an individual benchmark, set variable W or S to 0. This is only for debugging purposes.

Developed just for fun by Kenneth Karlsson. (kenneth.karlsson@workaholics.se)\n" && exit 
 
################################### SET VARIABLES ############################################### 
set -o nounset
T=                                             # Type of system: S for Server or W for Workstation.
declare -i L=1                                 # Level 1 or 2.
declare -i W=1                                 # Workstation level  (1 or 2).
declare -i S=1                                 # Server level  (1 or 2).
E=                                             # Variable to check exit status of warning messages.
U=                                             # Harden system. U=Y will harden system. Default is blank.
B=                                             # Display benchmark details. 
Q=                                             # Run in quite mode without any user output or interaction.
NO=                                            # Cisecurity benchmark number.
BD=                                            # Show benchmark details.
SC=                                            # N if not scored.
DATE="$(date +%Y%m%d-%H%M)"                    # Log files are saved with date & tmp extension.
CISDIR="$(dirname $0)"                         # Folder for cis script.
LOGDIR="${CISDIR}/log"                         # Name of log folder.
CISLOG="${LOGDIR}/cis-${DATE}.log"             # Name of log-file for all messages.
CISWARNLOG="${LOGDIR}/ciswarn-${DATE}.log"     # Name of log-file for all warning messages. If empty then system is hardened.
CISRC="${CISDIR}/.cisrc"                       # This file must be in disk partition with exec permissions.
CISRCNO=65                                     # Number of paramters in .cisrc file.
TMP1=/tmp/cistmp1.$$                           # Temp file 1.
TMP2=/tmp/cistmp2.$$                           # Temp file 2.
[[ -d ${LOGDIR} ]] || mkdir -m 600 ${LOGDIR}   # Create logfile directory.
> ${CISLOG}
> ${CISWARNLOG}

################################### SET .CISRC FILE DEFAULT VARIABLES ########################### 
apt list --installed 2> /dev/null | grep -q net-tools
(($? != 0)) && echo "net-tools is not installed. Please install before running script as ifconfig is required." && exit 1

[[ -s ${CISRC} ]] || {
    echo -e "#### Setup of computer specific parameters in ${CISRC} ####" >  ${CISRC}
    IFS=.;read  IP1 IP2 IP3 IP4 SM1 SM2 SM3 SM4 <<< $(ifconfig | grep inet | grep -v 127 | awk {'print $2"."$4'});IFS=
    SMASK="$(echo $(echo "obase=2;${SM1}" | bc)$(echo "obase=2;${SM2}" | bc)$(echo "obase=2;${SM3}" | bc)$(echo "obase=2;${SM4}" | bc) | sed s/0//g)"
    INTNETWORK=$((IP1 & SM1)).$((IP2 & SM2)).$((IP3 & SM3)).$((IP4 & SM4))/${#SMASK}

    apt list --installed 2> /dev/null | grep -q ubuntu-desktop
    case $? in
        0) echo -e 'TL="W1"                                            # Type of system and level S1, S2, W1, W2.  ' >> ${CISRC}
           echo -e 'SX11="Y"                                           # Set to Y to keep x11 and desktop.         ' >> ${CISRC}
           echo -e 'SAVAHI="Y"                                         # Set to Y to keep Apple Avahi.             ' >> ${CISRC} ;;
        *) echo -e 'TL="S1"                                            # Type of system and level S1, S2, W1, W2.  ' >> ${CISRC}
           echo -e 'SX11=""                                            # Set to Y to keep x11 and desktop.         ' >> ${CISRC}
           echo -e 'SAVAHI=""                                          # Set to Y to keep Apple Avahi.             ' >> ${CISRC} ;;
    esac


    apt list --installed 2> /dev/null | grep -q openssh-server
    case $? in
        0) echo -e 'SSSHD="Y"                                          # Set to Y to keep ssh server.              ' >> ${CISRC} ;;
        *) echo -e 'SSSHD=""                                           # Set to "" to remove ssh server.           ' >> ${CISRC} ;;
    esac


    echo -e 'SCUPS=""                                           # Set to Y to keep cups server.             ' >> ${CISRC}
    echo -e 'SDHCPD=""                                          # Set to Y to keep dhcp server.             ' >> ${CISRC}
    echo -e 'SSLAPD=""                                          # Set to Y to keep slapd server.            ' >> ${CISRC}
    echo -e 'SNFS=""                                            # Set to Y to keep nfs server.              ' >> ${CISRC}
    echo -e 'SBIND=""                                           # Set to Y to keep bind9 server.            ' >> ${CISRC}
    echo -e 'SVSFTPD=""                                         # Set to Y to keep vsftp server.            ' >> ${CISRC}
    echo -e 'SAPACHE=""                                         # Set to Y to keep apache server.           ' >> ${CISRC}
    echo -e 'SDOVECOT=""                                        # Set to Y to keep imap and pop3.           ' >> ${CISRC}
    echo -e 'SSAMBA=""                                          # Set to Y to keep samba server.            ' >> ${CISRC}
    echo -e 'SSQUID=""                                          # Set to Y to keep squid proxy server.      ' >> ${CISRC}
    echo -e 'SSNMPD=""                                          # Set to Y to keep snmp server.             ' >> ${CISRC}
    echo -e 'SRSYNC=""                                          # Set to Y to keep rsync server.            ' >> ${CISRC}
    echo -e 'SNIS=""                                            # Set to Y to keep nis server.              ' >> ${CISRC}
    echo -e 'SRPC=""                                            # Set to Y to keep rpc server.              ' >> ${CISRC}
    echo -e 'PDCCP=""                                           # Set to Y to prevent disabling DCCP.       ' >> ${CISRC}
    echo -e 'PSCTP=""                                           # Set to Y to prevent disabling SCTP.       ' >> ${CISRC}
    echo -e 'PRDS=""                                            # Set to Y to prevent disabling SRDS.       ' >> ${CISRC}
    echo -e 'PTIPC=""                                           # Set to Y to prevent disabling TIPC.       ' >> ${CISRC}
    echo -e 'PBGP=""                                            # Set to Y to prevent disabling BGP.        ' >> ${CISRC}
    echo -e 'U=""                                               # Set to Y to harden system automatically.  ' >> ${CISRC}
    echo -e 'Q=""                                               # Run in quite mode.                        ' >> ${CISRC}
    echo -e 'B=""                                               # Display benchmark details.                ' >> ${CISRC}
    echo -e 'SUGROUP="sugroup"                                  # Set pam default su group.                 ' >> ${CISRC}
    echo -e "SUDOUSR="${SUDO_USER}"                             # Set pam default su user.                  " >> ${CISRC}
    echo -e 'CISTMOUT="900"                                     # Set user shell timeout.                   ' >> ${CISRC}
    echo -e 'SSHTMOUT="300"                                     # Set ssh ClientAliveInterval               ' >> ${CISRC}
    echo -e 'SSHCOMAX="3"                                       # Set ssh ClientAliveCountMax               ' >> ${CISRC}
    echo -e 'SSHMAXSS="10"                                      # Set ssh MaxSessions.                      ' >> ${CISRC}
    echo -e 'SL="rsyslog"                                       # Syslog server can be rsyslog or syslog-ng.' >> ${CISRC}
    echo -e 'FW="ufw"                                           # Firewall can be iptables,nftables or ufw. ' >> ${CISRC}
    echo -e 'PFW="Y"                                            # Update firewall rules.                    ' >> ${CISRC}
    echo -e '                                                   # Change PFW to N after first fw update.    ' >> ${CISRC}
    echo -e 'GRP="Y"                                            # Update bootloader password                ' >> ${CISRC}
    echo -e 'GRU="Y"                                            # Enable unrestricted boot                  ' >> ${CISRC}
    echo -e 'GRF="40_custom"                                    # Grub custom config file                   ' >> ${CISRC}
    echo -e 'IPV6=""                                            # Set to Y to enable IPv6.                  ' >> ${CISRC}
    echo -e 'NT="systemd"                                       # NTP client can be ntp,chrony or systemd.  ' >> ${CISRC}
    echo -e 'LOGHOST=""                                         # Set remote log host.                      ' >> ${CISRC}
    echo -e 'LOGUDP="514"                                       # Set remote log host udp port.             ' >> ${CISRC}
    echo -e 'LOGTCP=""                                          # Set remote log host tcp port.             ' >> ${CISRC}
    echo -e 'PAMRETRY="3"                                       # Set PAM retries.                          ' >> ${CISRC}
    echo -e 'PAMMINLEN="14"                                     # Set PAM password length.                  ' >> ${CISRC}
    echo -e 'PAMDCREDIT="-1"                                    # Set PAM to at least 1 digit.              ' >> ${CISRC}
    echo -e 'PAMUCREDIT="-1"                                    # Set PAM to at least 1 uppercase.          ' >> ${CISRC}
    echo -e 'PAMOCREDIT="-1"                                    # Set PAM to at least 1 special.            ' >> ${CISRC}
    echo -e 'PAMLCREDIT="-1"                                    # Set PAM to at least 1 lowercase.          ' >> ${CISRC}
    echo -e 'PAMDENY="5"                                        # Set PAM to no of failed logins.           ' >> ${CISRC}
    echo -e 'PAMUNLOCK="900"                                    # Set PAM to locked time.                   ' >> ${CISRC}
    echo -e 'PAMHISTORY="5"                                     # Set PAM remembered password history.      ' >> ${CISRC}
    echo -e 'PAMENCRYPT="sha512"                                # Set PAM encryption key.                   ' >> ${CISRC}
    echo -e 'PASSMAXDAYS="365"                                  # Set password expiration days.             ' >> ${CISRC}
    echo -e 'PASSMINDAYS="7"                                    # Set Minimun days between password changes.' >> ${CISRC}
    echo -e 'PASSWARNDAYS="7"                                   # Set password expiration warning days.     ' >> ${CISRC}
    echo -e 'PASSINACTIVE="30"                                  # Set password inactive period.             ' >> ${CISRC}
    echo -e "INTNETWORK=\"${INTNETWORK}\"                       # Internal network.                         " >> ${CISRC}
    echo -e 'MAXLOGFILE="8"                                     # Maximum size of the audit log file.       ' >> ${CISRC}
    echo -e 'MAXLOGAGE="10"                                     # Set max age for logrotate.                ' >> ${CISRC}
    echo -e 'SPACELEFT="email"                                  # Space_left_action in audit log.           ' >> ${CISRC}
    echo -e 'ACTIONMAILACCT="root"                              # action_mail_acctt in audit log.           ' >> ${CISRC}
    echo -e 'ADMINSPACELEFT="halt"                              # Admin_space_left_action in audit log.     ' >> ${CISRC}
    echo -e 'ROOTLOGIN="console tty1 tty2 tty3 tty4 tty5 tty6"  # Secure root login.                        ' >> ${CISRC}

    while IFS= read -r FILE; do
        printf '##SUID## %s\n' "${FILE}" >> ${CISRC}
    done < <(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null | sort)

    while IFS= read -r FILE; do
        printf '##SGID## %s\n' "${FILE}" >> ${CISRC}
    done < <(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null | sort)

    while IFS= read -r FILE; do
        printf '##APTK## %s\n' "${FILE}" >> ${CISRC}
    done < <(apt-key list 2>/dev/null)

    echo -e "\nCISRC file ${CISRC} has now be created. Edit to suit system requirements."
    echo -e "\nDO NOT EXECUTE SCRIPT ON PRODUCTION SERVERS IN UPDATE MODE.\n"
    echo -e "Make sure parameter INTNETWORK is set right to allow ssh remote login."
    echo -e "Check sshd settings hosts.allow and hosts.deny before logging out."
    echo -e "Make sure you can still log in after executing in update mode before restarting."
    echo -e "\nRestart $0\n"
    chmod 700 ${CISRC}
    exit
}

[[ ! -s ${CISRC} ]] && echo -e "Could not find ${CISRC}. Check folder and file permissions." && exit 1

CISRCCHECK=$(grep -v '##' .cisrc | wc -l)
if [[ ${CISRCCHECK} -ne ${CISRCNO} ]]; then
    echo "The number of parameters in ${CISRC} are ${CISRCCHECK} but should be ${CISRCNO}."
    echo "Please review ${CISRC} or delete it in order to recreate it."
    exit 1
fi

. ${CISRC}

(echo $@ | grep -qi "\-*u") && U="Y"
(echo $@ | grep -qi "\-*q") && Q="Y"
(echo $@ | grep -qi "\-*b") && B="Y"
(echo $@ | grep -qi "\-s1") && TL="S1"
(echo $@ | grep -qi "\-s2") && TL="S2"
(echo $@ | grep -qi "\-w1") && TL="W1"
(echo $@ | grep -qi "\-w2") && TL="W2"

T=$(echo ${TL} | cut -c1)
L=$(echo ${TL} | cut -c2)

########################################### FUNCTIONS ########################################### 

# Check for update mode
function upd() {
    [[ ${U} ]] || return 1
}

# Check for quite mode
function qte() {
    [[ ${Q} ]] || return 1
}

# Check for warning error messages
function err() {
    [[ ${E} ]] || return 1
}

# Check if firewall is to be updated
function pfw() {
    upd || PFW=
    [[ ${PFW} ]] || return 1
}

# Print log information on screen and add to log file
function prn() {
    qte || printf "%-12s %-s\n" "${NO}" "${1}"
    printf "%-12s %-s\n" "${NO}" "${1}" >> ${CISLOG}
}

# Print warning information on screen and add to warning log file.
function prw() {
    qte || tput bold
    qte || printf "%-12s %-s\n" "${NO}" "${1}"
    qte || tput sgr0
    printf "%-12s %-s\n" "${NO}" "${1}" >> ${CISLOG}
    printf "%-12s %-s\n" "${NO}" "${1}" >> ${CISWARNLOG}
    E=Y
}

# Checks profile level for each benchmark. Level value can be 1 or 2 and is set with parameter W and S.
# Set variable W or S on benchmark to 3 to skip indivual benchmarks. 
# Set variable W or S on benchmark to 0 to exit from script.
function lev() {
    [[ -e ${TMP1} ]] && rm ${TMP1}
    [[ -e ${TMP2} ]] && rm ${TMP2}
    if [[ ${W} -eq 0 ]] || [[ ${S} -eq 0 ]]; then
        echo "Exiting from ${NO}."
        exit
    fi
    if [[ ${T} == W && ${W} -le ${L} ]] || [[ ${T} == S && ${S} -le ${L} ]]; then
        SCP="${SC/N/Not }Scored"
        [[ ${B} ]] && printf "%-12s :%-8s :%-8s :%-12s :%-s\n" "${NO}" "WS = ${W}" "SV = ${S}" "${SCP}" "${BD}" | tee -a ${CISLOG}
        return 0
    else
        return 1
    fi
}

# Update-grub changes grub.cfg permissions. This function reverts them to 400
function update_grub() {
    upd && update-grub 2> /dev/null
    upd && chmod 400 /boot/grub/grub.cfg
}

# Disables kernel modules.
# Parameter 1 = Name of kernel module.
function update_modprobe() {
    modprobe --showconfig | grep -q -E "install\s${1}"
    case $? in
        0)  prn "File /etc/modprobe.d/${1} is already updated." ;;
        *)  upd || prw "File /etc/modprobe.d/${1}.conf needs to be created."
            upd && prw "Updating /etc/modprobe.d/${1}.conf with install ${1} /bin/true."
            upd && echo "install ${1} /bin/true" > /etc/modprobe.d/${1}.conf ;;
    esac
}

# Update user account information.
# Parameter 1 = (4=mindays,5=maxdays, 6=warndays,7=inactive)
# Parameter 2 = value which is extracted from .cisrc file.

function update_chage() {
    local CHECK=
    local USR=
    local NAME=
    grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | while read USR
    do
        case ${1} in
            0)  CHECK=$(chage -l  ${USR} | grep ^Last | awk -F: {'print $2'})
                CHECK=$(date -d "${CHECK}" +"%Y%m%d")
                if [[ ${CHECK} -gt ${2} ]]; then
                    prw "Last password change for ${USR} is in the future (${CHECK}). CHECK SYSTEM DATE!"
                else
                    prn "Last password change for ${USR} is ${CHECK}."
                fi ;;
            [4-7]) CHECK=$(grep ^${USR} /etc/shadow | cut -d: -f${1})
                NAME=$(echo ${1} | sed 's/4/mindays/g;s/5/maxdays/g;s/6/warndays/g;s/7/inactive/g')
                if [[ ${CHECK} -eq ${2} ]]; then
                    prn "Password ${NAME} for ${USR} is already set to ${2}."
                else
                    upd || prw "Password ${NAME} for ${USR} is set to ${CHECK} and needs to be changed to ${2}."
                    upd && prw "Setting password ${NAME} for ${USR} to ${2}."
                    upd && chage --${NAME}  ${2} ${USR}
                fi ;;
        esac
    done
}

# Returns status of a systemctl service.
# Parameter 1 = service name
function check_systemctl() {
    if [[ $(systemctl is-enabled ${1} 2>/dev/null) = "enabled" ]]; then
        prn "System ${1} is enabled."
    else
        prw "System ${1} is not enabled."
    fi
}

# Checks fstab for partition information. 
# Parameter 1 = file system name
function check_fstab() {
    grep -q -E "\s${1}\s" /etc/fstab
    case $? in
        0)  prn "Found ${1} filesystem in /etc/fstab." ;;
        *)  prn "Filesystem ${1} is not a separate partition. This is not recommended for level 2." ;;
    esac
}

# Updates fstab partition information.
# Parameter 1 = file system name
# Parameter 2 = partition values (defaults,nodev,nosuid,noexec)
function update_fstab() {
    $(grep -q -E "\s${1}\s" /etc/fstab) && (
        grep -E "\s${1}\s" /etc/fstab | grep -q -E "\s${2}\s"
        case $? in
            0)  prn "Found ${1} filesystem. Already updated with ${2}." ;;
                *)  upd || prw "Found ${1} filesystem. /etc/fstab needs to be updated with ${2}."
                    upd && prw "Updating ${1} filesystem in /etc/fstab with ${2}."
                    upd && sed -i "$(awk -F" " '($2 == "'"$1"'" && $1 != "#") {print NR}' /etc/fstab)s/$(awk -F" " '($2 == "'"$1"'" && $1 != "#") {print $4}' /etc/fstab)/${2}/" /etc/fstab ;;
        esac
    )
}

# Deletes file if it exists.
# Parameter 1 = file name
function delete_file() {
    if  [[ -s "${1}" ]]; then
        upd || prw "File ${1} needs to be deleted."
        upd && prw "Deleting file ${1}"
        upd && rm ${1}
    else
        prn "File ${1} does not exist."
    fi
}

# Checks and updates file permissions and owner. Creates file if file is missing.
# Parameter 1 = file name
# Parameter 2 = user name
# Parameter 3 = group name
# Parameter 4 = file permissions
# Parameter 5 = Text to be added to first line if file is missing
function update_file() {
    local CHECK 
    if  [[ ! -s "${1}" ]]; then
        upd || prw "File ${1} is missing or empty. This file needs to be created."
        upd && prw "File ${1} is missing. Creating new file."
        upd && touch ${1}
        upd && chown ${2}:${3} ${1}
        upd && chmod ${4} ${1}
        upd && [[ $# -ge 5 ]] && echo -e ${5} > ${1}
    else
        CHECK=
        CHECK=$(stat -c "%U %G %a" ${1})
        case ${CHECK} in
            "${2} ${3} ${4}")   prn "File ${1} has the right permissions. ${2} ${3} ${4}" ;;
            *)                  upd || prw "File ${1} has the wrong permissions: ${CHECK}. This needs to be changed to ${2} ${3} ${4}"
                                upd && prw "File ${1} has the wrong permissions: ${CHECK}. Changing to ${2} ${3} ${4}"
                                upd && chown ${2}:${3} ${1}
                                upd && chmod ${4} ${1} ;;
        esac
    fi
}

# Updates message file  with standard text.
# Parameter 1 = file name (motd,issue,issue.net)
function update_message() {
    if  [[ ! -s "${1}" ]]; then
        upd || prw "File ${1} not found. It needs to be updated with standard text."
        upd && prw "File ${1} not found. Updating with standard text."
        upd && echo -e "Authorized use only. All activity may be monitored and reported.\n" > ${1}
    else
        grep -E -q '(\\v|\\r|\\m|\\s|Ubuntu)' ${1}
        case $? in
            0)  upd || prw "File ${1} contains unauthorized text. It needs to be updated with a standard text."
                upd && prw "File ${1} contains unauthorized text. Updating with standard a text."
                upd && echo -e "\nAuthorized use only. All activity may be monitored and reported.\n" > ${1} ;;
        esac
    fi
}

# Installs package if missing
# Parameter 1 = package name
function install_package() {
    apt list --installed 2> /dev/null | grep -q "^${1}\/"
        case $? in
            0)  systemctl status ${1} > /dev/null 2>&1
                case $? in
                    0)  prn "Package ${1} is already installed and active." ;;
                    3)  prn "Package ${1} is already installed but not active."
                        sleep 2
                        systemctl enable ${1} 2> /dev/null
                        systemctl start  ${1} 2> /dev/null ;;
                    *)  prn "Package ${1} is already installed but cant be started by systemctl." ;;
                esac ;;
            *)  upd || prw "Package ${1} is not installed. It needs to be installed." 
                upd && prw "Package ${1} is not installed. Installing now." 
                upd && apt -y install ${1}
                upd && systemctl enable ${1} > /dev/null 2>&1
                upd && systemctl start ${1} > /dev/null 2>&1 ;;
        esac
}

# Disables package
# Parameter 1 = package name
function disable_package() {
    apt list --installed 2> /dev/null | grep -q "^${1}\/"
    case $? in
        0)  systemctl status ${1} > /dev/null 2>&1
            case $? in
                0)  upd || prw "Package ${1} is installed and active. It needs to be disabled." 
                    upd && prw "Package ${1} is installed and active. Disabling." 
                    upd && systemctl stop ${1} 2> /dev/null
                    upd && systemctl disable  ${1} 2> /dev/null ;;
                3)  prn "Package ${1} is already disabled." ;;
                *)  prn "Package ${1} cant be stopped by systemctl." ;;
            esac ;;
        *)  prn "Package ${1} is not installed." ;;
    esac
}

# Removes package from system
# Parameter 1 = package name
function remove_package() {
    #dpkg -l ${1} > /dev/null 2>&1
    apt list --installed 2> /dev/null | grep -q "^${1}\/"
    case $? in
        0)  upd || prw "Package ${1} is installed and needs to be removed." 
            upd && prw "Package ${1} is installed and will be removed." 
            upd && [[ ${1} = prelink ]] && prelink -ua
            upd && apt  purge ${1}
            upd && apt -y autoremove ${1} ;;
        *)  prn "Package ${1} is not installed." ;;
    esac
}

# Updates information in conf files. 
# Parameter 1 = file name
# Parameter 2 = search text
# Parameter 3 = replacement text
# If search text is missing in file then replacement text is added to file.
# If replacment text parameter is empty then copy search text to replacement text.
function update_conf() {
    local STR
    local REP
    [[ $# -lt 3 ]] && REP=${2} || REP=${3}
    [[ -s ${1} ]] || update_file ${1} root root 440 '# Created by Cisecurity remediation script'
    if [[ -s ${1} ]]; then
        if [[ $(grep "^${2}" ${1} | wc -l) -gt 1 ]]; then
            prw "File ${1} has several rows with:${2}. Edit file manually."
        else
            STR=$(grep "^${2}" "${1}")
            case $? in
                0)  if  [[ ${STR} = ${REP} ]]; then
                        prn "File ${1} already contains: ${REP}."
                    else
                        upd || prw "File ${1} has:${STR}. This needs to be changed to:${REP}."
                        upd && prw "File ${1} has:${STR}. Changing to:${REP}."
                        upd && sed -i "/^${STR}/ c ${REP}" ${1}
                    fi ;;
                *)  upd || prw "File ${1} does not contain: ${REP}. It needs to be added."
                    upd && prw "File ${1} does not contain: ${REP}. Adding!"
                    upd && sed -i "$ a ${REP}" ${1} ;;
            esac
        fi    
    fi    
}

######################################## END OF FUNCTIONS ####################################### 

NO=1.1.1.1;   W=1; S=1; E=; SC=;  BD='Ensure mounting of cramfs filesystems is disabled'
lev && (update_modprobe cramfs) 

NO=1.1.1.2;   W=1; S=1; E=; SC=;  BD='Ensure mounting of freevxfs filesystems is disabled'
lev && (update_modprobe freevxfs)

NO=1.1.1.3;   W=1; S=1; E=; SC=;  BD='Ensure mounting of jffs2 filesystems is disabled'
lev && (update_modprobe jffs2)

NO=1.1.1.4;   W=1; S=1; E=; SC=;  BD='Ensure mounting of hfs filesystems is disabled'
lev && (update_modprobe hfs)

NO=1.1.1.5;   W=1; S=1; E=; SC=;  BD='Ensure mounting of hfsplus filesystems is disabled'
lev && (update_modprobe hfsplus)

NO=1.1.1.6;   W=1; S=1; E=; SC=;  BD='Ensure mounting of squashfs filesystems is disabled'
lev && (update_modprobe squashfs)

NO=1.1.1.7;   W=1; S=1; E=; SC=;  BD='Ensure mounting of udf filesystems is disabled'
lev && (update_modprobe udf)

NO=1.1.1.8;   W=2; S=2; E=; SC=;  BD='Ensure mounting of FAT filesystems is limited'
lev && (update_modprobe vfat)

NO=1.1.2;     W=1; S=1; E=; SC=;  BD='Ensure /tmp is configured'
lev && (check_fstab /tmp) 

NO=1.1.3;     W=1; S=1; E=; SC=;  BD='Ensure nodev option set on /tmp partition'
lev && (update_fstab /tmp 'defaults,nodev,nosuid,noexec')

NO=1.1.4;     W=1; S=1; E=; SC=;  BD='Ensure nosuid option set on /tmp partition'
lev  # Updated in 1.1.3

NO=1.1.5;     W=1; S=1; E=; SC=;  BD='Ensure noexec option set on /tmp partition'
lev  # Updated in 1.1.3

NO=1.1.6;     W=2; S=2; E=; SC=;  BD='Ensure separate partition exists for /var'
lev && (check_fstab /var)

NO=1.1.7;     W=2; S=2; E=; SC=;  BD='Ensure separate partition exists for /var/tmp'
lev && (check_fstab /var/tmp)

NO=1.1.8;     W=1; S=1; E=; SC=;  BD='Ensure nodev option set on /var/tmp partition'
lev && (update_fstab /var/tmp 'defaults,nodev,nosuid,noexec')

NO=1.1.9;    W=1; S=1; E=; SC=;  BD='Ensure nosuid option set on /var/tmp partition'
lev  # Updated in 1.1.9

NO=1.1.10;    W=1; S=1; E=; SC=;  BD='Ensure noexec option set on /var/tmp partition'
lev  # Updated in 1.1.9

NO=1.1.11;    W=2; S=2; E=; SC=;  BD='Ensure separate partition exists for /var/log'
lev && (check_fstab /var/log) 

NO=1.1.12;    W=2; S=2; E=; SC=;  BD='Ensure separate partition exists for /var/log/audit'
lev && (check_fstab /var/log/audit)

NO=1.1.13;    W=2; S=2; E=; SC=;  BD='Ensure separate partition exists for /home'
lev && (check_fstab /home)
 
NO=1.1.14;    W=1; S=1; E=; SC=;  BD='Ensure nodev option set on /home partition'
lev && (update_fstab /home 'defaults,nodev')

NO=1.1.15;    W=1; S=1; E=; SC=;  BD='Ensure nodev option set on /dev/shm partition'
lev && (
    mount | grep -q -E "\s/dev/shm\s"
    case $? in
        0)  prn "Found /dev/shm filesystem in mount." 
            grep -q -E "\s/dev/shm\s" /etc/fstab
            case $? in
                0)  prn "/dev/shm found in /etc/fstab." 
                    update_fstab /dev/shm 'defaults,nodev,nosuid,noexec';;
                *)  upd || prw "/dev/shm needs to be added to /etc/fstab"
                    upd && prw "Adding /dev/shm to /etc/fstab"
                    upd && sed -i "$ a tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" /etc/fstab
                    upd && mount -o remount /dev/shm ;;
                esac ;;
        *)    prw "No /dev/shm mounted. Check system." ;;
    esac
)

NO=1.1.16;    W=1; S=1; E=; SC=;  BD='Ensure nosuid option set on /dev/shm partition'
lev  # Updated in 1.1.15

NO=1.1.17;    W=1; S=1; E=; SC=;  BD='Ensure noexec option set on /dev/shm partition'
lev  # Updated in 1.1.15

NO=1.1.18;    W=1; S=1; E=; SC=N; BD='Ensure nodev option set on removable media partitions'
lev && (update_fstab /dev/cdrom 'defaults,nodev,nosuid,noexec')

NO=1.1.19;    W=1; S=1; E=; SC=N; BD='Ensure nosuid option set on removable media partitions'
lev  # Updated in 1.1.18

NO=1.1.20;    W=1; S=1; E=; SC=N; BD='Ensure noexec option set on removable media partitions'
lev  # Updated in 1.1.18

NO=1.1.21;    W=1; S=1; E=; SC=N; BD='Ensure sticky bit is set on all world-writable directories'
lev && (
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | grep -q "/"
    (($? == 0)) && {
        upd  || prw "Some world-writable folders did not have sticky bit set. This needs to be fixed"
        upd  && prw "Some world-writable folders did not have sticky bit set. Updating!"
        upd  && df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
    }
    err  || prn "All world-writable folders have their sticky bit set"
)

NO=1.1.22;    W=2; S=1; E=; SC=;  BD='Disable Automounting'
lev && (remove_package autofs)

NO=1.1.23;     W=2; S=1; E=; SC=;  BD='Disable USB Storage'
lev && (update_modprobe usb_storage)

NO=1.2.1;     W=1; S=1; E=; SC=N; BD='Ensure package manager repositories are configured'
lev && (
    apt-cache policy | grep http | grep -vq "ubuntu.com"
    (($? != 1)) && prw "Found other repositories. Check apt-cache policy."
    err         || prn "Only Ubuntu repositories installed"
)

NO=1.2.2;     W=1; S=1; E=; SC=N; BD='Ensure GPG keys are configured'
lev && (
    apt-key list 2> /dev/null >${TMP2}
    grep '##APTK##' ${CISRC} | cut -c10- > ${TMP1}
    diff ${TMP1} ${TMP2} > /dev/null 2>&1
    case $? in
        0)  prn "No extra apt keys found." ;;
        *)  prw "Unknown apt key found."
            diff ${TMP1} ${TMP2} >> ${CISWARNLOG}
            upd && (
                read -p "Do you want to reset apt key baseline in ${CISRC} N/y: " ANS
                case ${ANS} in
                    [yY]*)  sed -i "/^##APTK##/ d " ${CISRC}
                            while IFS= read FILE; do
                                printf '##APTK## %s\n' "${FILE}" >> ${CISRC}
                            done < <(apt-key list 2>/dev/null) ;;
                esac
            ) ;;
    esac
)


NO=1.3.1;     W=1; S=1; E=; SC=;  BD='Ensure sudo is installed'
lev && (
    install_package sudo
    grep -q -E "^#includedir\s/etc/sudoers.d" /etc/sudoers
    case $? in
        0)  prn "Folder /etc/sudoers.d included in /etc/sudoers" ;;
        *)  prw "Folder /etc/sudoers.d is not included in /etc/sudoers. Edit manually with visudo." ;;
    esac
    update_file /etc/sudoers.d/sudoers root root 440 '# Created by Cisecurity remediation script'
)

NO=1.3.2;     W=1; S=1; E=; SC=;  BD='Ensure sudo commands use pty'
lev && (update_conf /etc/sudoers.d/sudoers 'Defaults use_pty')

NO=1.3.3;     W=1; S=1; E=; SC=;  BD='Ensure sudo log file exists'
lev && (update_conf /etc/sudoers.d/sudoers 'Defaults logfile="/var/log/sudo.log"')

NO=1.4.1;     W=1; S=1; E=; SC=;  BD='Ensure AIDE is installed'
lev && (
    install_package aide
    install_package aide-common
    if  [[ ! -f /var/lib/aide/aide.db.new ]]; then
        upd || prw "Aideinit needs to be executed." 
        upd && prn "Executing aideinit. This could take a long time." 
        upd && aideinit
    fi
)

NO=1.4.2;     W=1; S=1; E=; SC=;  BD='Ensure filesystem integrity is regularly checked'
lev && (
    if  [[ -f /etc/cron.daily/aide ]]; then
        prn "Aide crontab is already installed."
    else
        prw "Aide crontab /etc/cron.daily/aide is not installed. Fix manually."
    fi
)

NO=1.5.1;     W=1; S=1; E=; SC=;  BD='Ensure permissions on bootloader config are configured'
lev && (update_grub)

NO=1.5.2;     W=1; S=1; E=; SC=;  BD='Ensure bootloader password is set'
lev && [[ $GRP ]] && (
    update_conf /etc/grub.d/10_linux 'CLASS="--class gnu-linux --class gnu --class os' 'CLASS="--class gnu-linux --class gnu --class os --unrestricted"'
    update_grub
    upd && (
        grep "^password_pbkdf2" -q /etc/grub.d/${GRF}
        case $? in
            0)  prn "Grub password is already set" ;;
            *)  echo -e "\n\nSet grub password. Use at least 15 characters.\n"
                grub-mkpasswd-pbkdf2 | tee ${TMP1} 
                grep "^PBKDF2" -q ${TMP1}
                case $? in
                    0)  update_conf /etc/grub.d/${GRF} "set superusers=${SUDOUSR:-root}"
                        echo -e "password_pbkdf2 ${SUDOUSR:-root} $(grep "^PBKDF2" ${TMP1} | awk -F "is " '{print $2}')" >> /etc/grub.d/${GRF}
                        update_grub ;;
                esac ;;
        esac
    )
)

NO=1.5.3;     W=1; S=1; E=; SC=;  BD='Ensure authentication required for single user mode'
lev && (
    grep -q "^root:[*\!]:" /etc/shadow
    case  $? in
        0)  upd || prw "Root password needs to be set."
            upd && prw "Please set root password. Use at least 15 characters."
            upd && passwd root ;;
    esac
    err         || prn "Root password is already set."
)

NO=1.5.4;     W=1; S=1; E=; SC=;  BD='Ensure interactive boot is not enabled'
lev  # Not available in Ubuntu

NO=1.6.1;     W=1; S=1; E=; SC=N; BD='Ensure XD/NX support is enabled'
lev && (
    journalctl  |  grep -q "protection: active"
    (($? != 0)) && prw "NX is not active. Check kernel."
    err         || prn "NX is active."
)

NO=1.6.2;     W=1; S=1; E=; SC=;  BD='Ensure address space layout randomization (ASLR) is enabled'
lev && (update_conf /etc/sysctl.d/local.conf 'kernel.randomize_va_space' 'kernel.randomize_va_space = 2')

NO=1.6.3;     W=1; S=1; E=; SC=;  BD='Ensure prelink is disabled'
lev && (remove_package prelink)

NO=1.6.4;     W=1; S=1; E=; SC=;  BD='Ensure core dumps are restricted'
lev && (
    update_conf /etc/security/limits.conf '*   hard    core    0'
    update_conf /etc/sysctl.d/local.conf 'fs.suid_dumpable' 'fs.suid_dumpable = 0'
    disable_package apport
)

NO=1.7.1.1;   W=1; S=1; E=; SC=;  BD='Ensure AppArmor is installed'
lev && (
    upd && install_package apparmor
    upd && install_package apparmor-utils
    upd && aa-enforce /etc/apparmor.d/*
)

NO=1.7.1.2;   W=1; S=1; E=; SC=;  BD='Ensure AppArmor is enabled in the bootloader configuration'
lev && (
    update_conf /etc/default/grub 'GRUB_CMDLINE_LINUX="apparmor' 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"'
    update_conf /etc/default/grub 'GRUB_CMDLINE_LINUX_DEFAULT' 'GRUB_CMDLINE_LINUX_DEFAULT="quiet"'
    update_grub
)
    
NO=1.7.1.3;   W=1; S=1; E=; SC=;  BD='Ensure all AppArmor Profiles are in enforce or complain mode'
lev && (
    upd && aa-complain /etc/apparmor.d/*
    qte || aa-status | grep complain
    qte && aa-status | grep complain >> ${CISLOG}
)
    
NO=1.7.1.4;   W=2; S=2; E=; SC=;  BD='Ensure all AppArmor Profiles are enforcing'
lev && (
    upd && aa-enforce /etc/apparmor.d/*
    qte || aa-status | grep enforce
    qte && aa-status | grep enforce >> ${CISLOG}
)
    
NO=1.8.1.1;   W=1; S=1; E=; SC=;  BD='Ensure message of the day is configured properly'
lev && (update_message /etc/motd)

NO=1.8.1.2;   W=1; S=1; E=; SC=;  BD='Ensure local login warning banner is configured properly'
lev && (update_message /etc/issue)

NO=1.8.1.3;   W=1; S=1; E=; SC=;  BD='Ensure remote login warning banner is configured properly'
lev && (update_message /etc/issue.net)

NO=1.8.1.4;   W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/motd are configured'
lev && (update_file /etc/motd root root 644)

NO=1.8.1.5;   W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/issue are configured'
lev && (update_file /etc/issue root root 644)

NO=1.8.1.6;   W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/issue.net are configured'
lev && (update_file /etc/issue.net root root 644)

NO=1.8.2;     W=1; S=1; E=; SC=;  BD='Ensure GDM login banner is configured'
lev && (
    if [[ -s /etc/gdm3/greeter.dconf-defaults ]]; then
        update_conf /etc/gdm3/greeter.dconf-defaults '\[org/gnome/login-screen\]'
        update_conf /etc/gdm3/greeter.dconf-defaults 'banner-message-enable' 'banner-message-enable=true'
        update_conf /etc/gdm3/greeter.dconf-defaults "banner-message-text" "banner-message-text='Authorized uses only. All activity may be monitored and reported.'"
        upd && dpkg-reconfigure gdm3
    else
        prn "Gnome is not installed."
    fi
)

NO=1.9;       W=1; S=1; E=; SC=N; BD='Ensure updates, patches, and additional security software are installed'
lev && (
    wget -q --spider http://google.com
    case $? in
        0)  apt -qq update > /dev/null 2>&1
            upd && prn "Installing $(apt list --upgradable 2> /dev/null | grep '/' | wc -l) patches"
            upd && apt -y upgrade
            upd && apt -y autoremove
            upd && apt -y autoclean
            upd || prn "Number of patches available for installation: $(apt list --upgradable 2> /dev/null | grep '/' | wc -l)" ;;
        *)  prn "The internet is not accessible" ;;
    esac
)

NO=2.1.1;     W=1; S=1; E=; SC=;  BD='Ensure xinetd is not installed'
lev && (remove_package xinetd)

NO=2.1.2;     W=1; S=1; E=; SC=;  BD='Ensure openbsd-inetd is not installed'
lev && (remove_package openbsd-inetd)

NO=2.2.1.1;   W=1; S=1; E=; SC=N; BD='Ensure time synchronization is in use'
lev && (
    case ${NT} in
        systemd) remove_package   ntp 
                 remove_package   chrony 
                 systemctl enable systemd-timesyncd.service
                 systemctl start  systemd-timesyncd.service ;;
        chrony)  remove_package   ntp 
                 install_package  chrony ;;
        ntp)     remove_package   chrony
                 install_package  ntp ;;
        *)       prw "${NT} is not set to systemd, chrony or ntp. Please correct parameters." ;;
    esac
)

NO=2.2.1.2;   W=1; S=1; E=; SC=;  BD='Ensure systemd-timesyncd is configured'
lev && [[ ${NT} = systemd ]] && (check_systemctl systemd-timesyncd.service) 

NO=2.2.1.3;   W=1; S=1; E=; SC=;  BD='Ensure chrony is configured'
lev && [[ ${NT} = chrony ]] && (
    prn "Edit /etc/chrony.d/chrony/chrony.conf manually if these settings are wrong."
    grep -E "^(server|pool)" /etc/chrony/chrony.conf
)

NO=2.2.1.4;   W=1; S=1; E=; SC=;  BD='Ensure ntp is configured'
lev && [[ ${NT} = ntp ]] && (
    update_conf /etc/ntp.conf 'restrict -4 default kod nomodify notrap nopeer noquery'
    update_conf /etc/ntp.conf 'restrict -6 default kod nomodify notrap nopeer noquery'
    update_conf /etc/init.d/ntp 'RUNASUSER=' 'RUNASUSER=ntp'
)

NO=2.2.2;     W=3; S=1; E=; SC=;  BD='Ensure X Window System is not installed'
lev && [[ -z ${SX11} ]] && (remove_package xserver-xorg*)

NO=2.2.3;     W=1; S=1; E=; SC=;  BD='Ensure Avahi Server is not enabled'
lev && [[ -z ${SAVAHI} ]] && (remove_package avahi-daemon)

NO=2.2.4;     W=2; S=1; E=; SC=;  BD='Ensure CUPS is not enabled'
lev && [[ -z ${SCUPS} ]] && (remove_package cups)

NO=2.2.5;     W=1; S=1; E=; SC=;  BD='Ensure DHCP Server is not enabled'
lev && [[ -z ${SDHCPD} ]] && (
        remove_package isc-dhcp-server
        remove_package isc-dhcp-server6
        remove_package udhcpd
)

NO=2.2.6;     W=1; S=1; E=; SC=;  BD='Ensure LDAP server is not enabled'
lev && [[ -z ${SSLAPD} ]] && (remove_package slapd)

NO=2.2.7;     W=1; S=1; E=; SC=;  BD='Ensure NFS and RPC are not enabled'
lev && [[ -z ${SNFS} ]] && (
        remove_package nfs-kernel-server
        remove_package rpcbind
)

NO=2.2.8;     W=1; S=1; E=; SC=;  BD='Ensure DNS Server is not enabled'
lev && [[ -z ${SBIND} ]] && (remove_package bind9)

NO=2.2.9;     W=1; S=1; E=; SC=;  BD='Ensure FTP Server is not enabled'
lev && [[ -z ${SVSFTPD} ]] && (remove_package vsftpd)

NO=2.2.10;    W=1; S=1; E=; SC=;  BD='Ensure HTTP server is not enabled'
lev && [[ -z ${SAPACHE} ]] && (remove_package apache2)

NO=2.2.11;    W=1; S=1; E=; SC=;  BD='Ensure email services are not enabled'
lev && [[ -z ${SDOVECOT} ]] && (
    remove_package dovecot-imapd
    remove_package dovecot-pop3d
)

NO=2.2.12;    W=1; S=1; E=; SC=;  BD='Ensure Samba is not enabled'
lev && [[ -z ${SSAMBA} ]] && (remove_package samba)

NO=2.2.13;    W=1; S=1; E=; SC=;  BD='Ensure HTTP Proxy Server is not enabled'
lev && [[ -z ${SSQUID} ]] && (remove_package squid)

NO=2.2.14;    W=1; S=1; E=; SC=;  BD='Ensure SNMP Server is not enabled'
lev && [[ -z ${SSNMPD} ]] && (remove_package snmpd)

NO=2.2.15;    W=1; S=1; E=; SC=;  BD='Ensure mail transfer agent is configured for local-only mode'
lev && (
    apt list --installed 2> /dev/null | grep -q postfix
    case $? in
        0)  if [[ ! -s /etc/postfix/main.cf ]]; then
                cp /etc/postfix/main.cf.proto /etc/postfix/main.cf
            fi
            update_conf /etc/postfix/main.cf 'inet_interfaces' 'inet_interfaces = loopback-only' ;;
        *)  prn "Postfix is not installed." ;;
    esac
)

NO=2.2.16;    W=1; S=1; E=; SC=;  BD='Ensure rsync service is not enabled'
lev && [[ -z ${SRSYNC} ]] && (remove_package rsync)

NO=2.2.17;    W=1; S=1; E=; SC=;  BD='Ensure NIS Server is not enabled'
lev && [[ -z ${SNIS} ]] && (remove_package nis)

NO=2.3.1;     W=1; S=1; E=; SC=;  BD='Ensure NIS Client is not installed'
lev && (remove_package ypbind)

NO=2.3.2;     W=1; S=1; E=; SC=;  BD='Ensure rsh client is not installed'
lev && (remove_package rsh-client)

NO=2.3.3;     W=1; S=1; E=; SC=;  BD='Ensure talk client is not installed'
lev && (remove_package talkd)

NO=2.3.4;     W=1; S=1; E=; SC=;  BD='Ensure telnet client is not installed'
lev && (remove_package telnet)

NO=2.3.5;     W=1; S=1; E=; SC=;  BD='Ensure LDAP client is not installed'
lev && (remove_package ldap-utils)

NO=2.4;     W=1; S=1; E=; SC=;  BD='Ensure nonessential services are removed or masked'
lev && (
    prn "Check list of listening open ports below."
    lsof -i -P -n | grep -v "(ESTABLISHED)" | tee -a ${CISLOG}
)

NO=3.2.1;     W=1; S=1; E=; SC=;  BD='Ensure packet redirect sending is disabled'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.all.send_redirects' 'net.ipv4.conf.all.send_redirects = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.default.send_redirects' 'net.ipv4.conf.default.send_redirects = 0'
)

NO=3.2.2;     W=1; S=1; E=; SC=;  BD='Ensure IP forwarding is disabled'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.ip_forward' 'net.ipv4.ip_forward = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.all.forwarding' 'net.ipv6.conf.all.forwarding = 0' 
)

NO=3.3.1;     W=1; S=1; E=; SC=;  BD='Ensure source routed packets are not accepted'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.all.accept_source_route' 'net.ipv4.conf.all.accept_source_route = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.default.accept_source_route' 'net.ipv4.conf.default.accept_source_route = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.all.accept_source_route' 'net.ipv6.conf.all.accept_source_route = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.default.accept_source_route' 'net.ipv6.conf.default.accept_source_route = 0'
)

NO=3.3.2;     W=1; S=1; E=; SC=;  BD='Ensure ICMP redirects are not accepted'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.all.accept_redirects' 'net.ipv4.conf.all.accept_redirects = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.default.accept_redirects' 'net.ipv4.conf.default.accept_redirects = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.all.accept_redirects' 'net.ipv6.conf.all.accept_redirects = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.default.accept_redirects' 'net.ipv6.conf.default.accept_redirects = 0'
)

NO=3.3.3;     W=1; S=1; E=; SC=;  BD='Ensure secure ICMP redirects are not accepted'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.all.secure_redirects' 'net.ipv4.conf.all.secure_redirects = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.default.secure_redirects' 'net.ipv4.conf.default.secure_redirects = 0'
)

NO=3.3.4;     W=1; S=1; E=; SC=;  BD='Ensure suspicious packets are logged'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.all.log_martians' 'net.ipv4.conf.all.log_martians = 1'
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.default.log_martians' 'net.ipv4.conf.default.log_martians = 1'
    if [[ -s /etc/ufw/sysctl.conf ]]; then
        grep -q ^net.ipv4.conf.all.log_martians /etc/ufw/sysctl.conf
        case $? in
            0) upd || prw 'File /etc/ufw/sysctl.conf overrides /etc/sysctl.conf with parameter net.ipv4.conf.all.log_martians. This must be fixed.'
               upd && prw 'File /etc/ufw/sysctl.conf overrides /etc/sysctl.conf with parameter net.ipv4.conf.all.log_martians. Fixing.'
               upd && sed -i "/^net.ipv4.conf.all.log_martians/ c #net.ipv4.conf.all.log_martians" /etc/ufw/sysctl.conf ;;
        esac
        grep -q ^net.ipv4.conf.default.log_martians /etc/ufw/sysctl.conf
        case $? in
            0) upd || prw '/etc/ufw/sysctl.conf overrides /etc/sysctl.conf with parameter net.ipv4.conf.default.log_martians. This must be fixed.'
               upd && prw '/etc/ufw/sysctl.conf overrides /etc/sysctl.conf with parameter net.ipv4.conf.default.log_martians. Fixing.'
               upd && sed -i "/^net.ipv4.conf.default.log_martians/ c #net.ipv4.conf.default.log_martians" /etc/ufw/sysctl.conf ;;
        esac
    fi
)

NO=3.3.5;     W=1; S=1; E=; SC=;  BD='Ensure broadcast ICMP requests are ignored'
lev && (update_conf /etc/sysctl.d/local.conf 'net.ipv4.icmp_echo_ignore_broadcasts' 'net.ipv4.icmp_echo_ignore_broadcasts = 1')

NO=3.3.6;     W=1; S=1; E=; SC=;  BD='Ensure bogus ICMP responses are ignored'
lev && (update_conf /etc/sysctl.d/local.conf 'net.ipv4.icmp_ignore_bogus_error_responses' 'net.ipv4.icmp_ignore_bogus_error_responses = 1')

NO=3.3.7;     W=1; S=1; E=; SC=;  BD='Ensure Reverse Path Filtering is enabled'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.all.rp_filter' 'net.ipv4.conf.all.rp_filter = 1'
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.conf.default.rp_filter' 'net.ipv4.conf.default.rp_filter = 1'
)

NO=3.3.8;     W=1; S=1; E=; SC=;  BD='Ensure TCP SYN Cookies is enabled'
lev && (update_conf /etc/sysctl.d/local.conf 'net.ipv4.tcp_syncookies' 'net.ipv4.tcp_syncookies = 1')

NO=3.3.9;     W=1; S=1; E=; SC=;  BD='Ensure IPv6 router advertisements are not accepted'
lev && (
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.all.accept_ra' 'net.ipv6.conf.all.accept_ra = 0'
    update_conf /etc/sysctl.d/local.conf 'net.ipv6.conf.default.accept_ra' 'net.ipv6.conf.default.accept_ra = 0'
)

NO=3.4.1;     W=1; S=1; E=; SC=N; BD='Ensure TCP Wrappers is installed'
lev && (install_package tcpd)

NO=3.4.2;     W=1; S=1; E=; SC=;  BD='Ensure /etc/hosts.allow is configured'
lev && [[ ${INTNETWORK} ]] && (update_conf /etc/hosts.allow "ALL: ${INTNETWORK}")

NO=3.4.3;     W=1; S=1; E=; SC=;  BD='Ensure /etc/hosts.deny is configured'
lev && $(grep -v  -E "^#|^$" /etc/hosts.allow | grep -q "[a-z,A-Z,0-9]") && (update_conf /etc/hosts.deny "ALL: ALL")

NO=3.4.4;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/hosts.allow are configured'
lev && (update_file /etc/hosts.allow root root 644)

NO=3.4.5;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/hosts.deny are configured'
lev && (update_file /etc/hosts.deny root root 644)

NO=3.5.1;     W=1; S=1; E=; SC=N; BD='Ensure DCCP is disabled'
lev && (update_modprobe dccp)

NO=3.5.2;     W=1; S=1; E=; SC=N; BD='Ensure SCTP is disabled'
lev && (update_modprobe sctp)

NO=3.5.3;     W=1; S=1; E=; SC=N; BD='Ensure RDS is disabled'
lev && (update_modprobe rds)

NO=3.5.4;     W=1; S=1; E=; SC=N; BD='Ensure TIPC is disabled'
lev && (update_modprobe tipc)

NO=3.6.1.1;   W=1; S=1; E=; SC=;  BD='Ensure a Firewall package is installed'
lev && (
    case ${FW} in
        ufw)        install_package ufw
                    remove_package iptables-persistent ;;
        nftables)   remove_package iptables
                    remove_package ufw
                    install_package nftables ;;
        iptables)   remove_package nftables
                    install_package iptables
                    install_package iptables-persistent
                    remove_package ufw ;;
        *)          prw "${FW} is not set to ufw, iptables or nftables. Please correct parameters." ;;
    esac
)

NO=3.6.2.1;   W=1; S=1; E=; SC=;  BD='Ensure ufw service is enabled'
lev && [[ ${FW} = ufw ]] && (
    pfw && (
        (ufw status | grep -qw "active") || ufw enable
        (ufw status | grep -qi "active") || prw "ufw needs to be enabled."
        [[ -z ${IPV6} ]] || (update_conf /etc/default/ufw 'IPV6' 'IPV6=yes')
        [[ -z ${IPV6} ]] && (update_conf /etc/default/ufw 'IPV6' 'IPV6=no')
    )
)

NO=3.6.2.2;   W=1; S=1; E=; SC=;  BD='Ensure default deny firewall policy'
lev && [[ ${FW} = ufw ]] && (
    pfw && ufw default deny incoming
    pfw && ufw default deny outgoing
    pfw && ufw default deny routed
)

NO=3.6.2.3;   W=1; S=1; E=; SC=;  BD='Ensure loopback traffic is configured' 
lev && [[ ${FW} = ufw ]] && (
    pfw && (
        ufw allow in on lo
        ufw allow out from lo
        ufw deny in from 127.0.0.0/8
        ufw deny in from ::1
    )
)

NO=3.6.2.4;   W=1; S=1; E=; SC=N;  BD='Ensure outbound connections are configured'
lev && [[ ${FW} = ufw ]] && (
    pfw && ufw allow out on all
    pfw || prw "ufw needs to be updated."
)

NO=3.6.2.5;   W=1; S=1; E=; SC=N;  BD='Ensure firewall rules exist for all open ports'
lev && [[ ${FW} = ufw ]] && (
# tcp
    while read PORT; do
        ufw status | grep "^${PORT}" | grep -q tcp
        case $? in
            0)  prn "ufw: TCP Port ${PORT} is already open." ;;
            *)  pfw || prn "ufw: Port ${PORT} might need to be opened."
                pfw && prw "ufw: Opening port ${PORT}."
                case ${PORT} in 
                    22) pfw && ufw allow proto tcp from ${INTNETWORK} to any port ${PORT} ;;
                    *)  pfw && ufw allow proto tcp to any port ${PORT} ;;
                esac ;;
        esac
    done < <(netstat -tnlp | grep "^tcp " | grep -v 127 | cut -d: -f2 | awk  '{print $1}')
# udp
    while read PORT; do
        ufw status | grep "^${PORT}" | grep -q udp
        case $? in
            0)  prn "ufw: TCP Port ${PORT} is already open." ;;
            *)  pfw || prn "ufw: Port ${PORT} might need to be opened."
                pfw && prw "ufw: Opening port ${PORT}."
                pfw && ufw allow proto udp to any port ${PORT} ;;
        esac
    done < <(netstat -tnlp | grep "^udp " | grep -v 127 | cut -d: -f2 | awk  '{print $1}')
)

NO=3.6.3.1;   W=1; S=1; E=; SC=N; BD='Ensure iptables are flushed'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && iptables -F
    pfw && ip6tables -F
)

NO=3.6.3.2;   W=1; S=1; E=; SC=;  BD='Ensure a table exists'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && nft create table inet filter 
)

NO=3.6.3.3;   W=1; S=1; E=; SC=;  BD='Ensure base chains exist'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && nft create chain inet filter input { type filter hook input priority 0 \; } 
    pfw && nft create chain inet filter forward { type filter hook forward priority 0 \; }
    pfw && nft create chain inet filter output { type filter hook output priority 0 \; }
)

NO=3.6.3.4;   W=1; S=1; E=; SC=;  BD='Ensure loopback traffic is configured'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && nft add rule inet filter input iif lo accept
    pfw && nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop
    pfw && nft add rule inet filter input ip6 saddr ::1 counter drop
)

NO=3.6.3.5;   W=1; S=1; E=; SC=;  BD='Ensure outbound and established connections are configured'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && nft add rule inet filter input ip protocol tcp ct state established accept
    pfw && nft add rule inet filter input ip protocol udp ct state established accept
    pfw && nft add rule inet filter input ip protocol icmp ct state established accept
    pfw && nft add rule inet filter output ip protocol tcp ct state new,related,established accept
    pfw && nft add rule inet filter output ip protocol udp ct state new,related,established accept
    pfw && nft add rule inet filter output ip protocol icmp ct state new,related,established accept
)

NO=3.6.3.6;   W=1; S=1; E=; SC=;  BD='Ensure default deny firewall policy'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && nft add rule inet incoming-traffic management tcp dport 22
    pfw && nft chain inet filter input { policy drop \; }
    pfw && nft chain inet filter forward { policy drop \; }
    pfw && nft chain inet filter output { policy drop \; }
)

NO=3.6.3.7;   W=1; S=1; E=; SC=;  BD='Ensure nftables service is enabled'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && systemctl enable nftables
)

NO=3.6.3.8;   W=1; S=1; E=; SC=;  BD='Ensure nftables rules are permanent'
lev && [[ ${FW} = "nftables" ]] && (
    pfw && update_conf /etc/sysconfig/nftables.conf 'include "/etc/nftables/nftables.rules"'
)
 
NO=3.6.4.1.1; W=1; S=1; E=; SC=;  BD='Ensure iptables packages are installed'
lev && [[ ${FW} = "iptables" ]] && (
    apt list --installed 2>/dev/null | grep -q iptables
    case $? in
            0)  prn "iptables is installed." ;;
            *)  prw "iptables is not installed." ;;
    esac
    apt list --installed 2> /dev/null | grep -q iptables-persistent
    case $? in
            0)  prn "iptables-persistent is installed." ;;
            *)  prw "iptables-persistent is not installed." ;;
    esac
)

NO=3.6.4.1.2; W=1; S=1; E=; SC=;  BD='Ensure nftables is not installed'
lev && [[ ${FW} = "iptables" ]] && (
    apt list --installed 2> /dev/null | grep -q nftables
    case $? in
            0)  prw "nftables is installed together with iptables. Please fix." ;;
            *)  prn "nftables is not installed together with iptables." ;;
    esac
)

NO=3.6.4.1.3; W=1; S=1; E=; SC=;  BD='Ensure Uncomplicated Firewall (UFW) is not installed or stopped and masked'
lev && [[ ${FW} = "iptables" ]] && (
    apt list --installed 2> /dev/null | grep -q ufw
    case $? in
            0)  prw "ufw is installed with iptables. Please replace with iptables-persistent." ;;
            *)  prn "ufw is not installed together with iptables-persistent." ;;
    esac
)

NO=3.6.4.2.1; W=1; S=1; E=; SC=;  BD='Ensure default deny firewall policy'
lev && [[ ${FW} = "iptables" ]] && (
    pfw || prn "Iptables. Default deny firewall policy might need to be configured."
    pfw && prn "Iptables. Configuring default deny firewall policy."
    pfw && iptables -P INPUT DROP
    pfw && iptables -P OUTPUT DROP
    pfw && iptables -P FORWARD DROP
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.6.4.2.2; W=1; S=1; E=; SC=;  BD='Ensure loopback traffic is configured'
lev && [[ ${FW} = "iptables" ]] && (
    pfw || prn "Iptables. Loopback traffic might need to be configured."
    pfw && prn "Iptables. Configuring loopback traffic."
    pfw && iptables -A INPUT -i lo -j ACCEPT
    pfw && iptables -A OUTPUT -o lo -j ACCEPT
    pfw && iptables -A INPUT -s 127.0.0.0/8 -j DROP
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.6.4.2.3; W=1; S=1; E=; SC=N; BD='Ensure outbound and established connections are configured'
lev && [[ ${FW} = "iptables" ]] && (
    pfw || prn "Iptables. Outbound and established connections might need to be configured."
    pfw && prn "Iptables. Configuring outbound and established connections."
    pfw && iptables -A OUTPUT -p tcp  -m state --state NEW,ESTABLISHED -j ACCEPT
    pfw && iptables -A OUTPUT -p udp  -m state --state NEW,ESTABLISHED -j ACCEPT
    pfw && iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
    pfw && iptables -A INPUT  -p tcp  -m state --state ESTABLISHED     -j ACCEPT
    pfw && iptables -A INPUT  -p udp  -m state --state ESTABLISHED     -j ACCEPT
    pfw && iptables -A INPUT  -p icmp -m state --state ESTABLISHED     -j ACCEPT
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.6.4.2.4; W=1; S=1; E=; SC=;  BD='Ensure firewall rules exist for all open ports'
lev && [[ ${FW} = "iptables" ]] && (
    pfw || prn "Iptables. Firewall rules for all open ports might need to be configured."
    pfw && prn "Iptables. Configuring firewall rules for all open ports."
# tcp
    while read PORT; do
        iptables -nL | grep ${PORT} | grep -q tcp 
        case $? in
            0)  prn "TCP Port ${PORT} is already open in iptables." ;;
            *)  pfw || prn "Iptables: Port ${PORT} might need to be opened."
                pfw && prw "Iptables: Opening port ${PORT} ."
                case ${PORT} in 
                    22) pfw && iptables -A INPUT --source ${INTNETWORK} -p tcp --dport 22 -j ACCEPT ;;
                    *)  pfw && iptables -A INPUT -p tcp --dport ${PORT} -j ACCEPT ;;
                esac ;;
        esac
    done < <(netstat -tnlp | grep "^tcp " | grep -v 127 | cut -d: -f2 | awk  '{print $1}')
# udp
    while read PORT; do
        iptables -nL | grep ${PORT} | grep -q udp 
        case $? in
            0)  prn "UDP Port ${PORT} is already open in iptables." ;;
            *)  pfw || prn "Iptables: Port ${PORT} might need to be opened."
                pfw && prw "Iptables: Opening port ${PORT} ."
                pfw && iptables -A INPUT -p udp --dport ${PORT} -j ACCEPT ;;
        esac
    done < <(netstat -tnlp | grep "^udp " | grep -v 127 | cut -d: -f2 | awk  '{print $1}')
    pfw && iptables -A INPUT -j DROP
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.6.4.3.1; W=1; S=1; E=; SC=;  BD='Ensure IPv6 default deny firewall policy'
lev && [[ ${FW} = "iptables" ]] && [[ ${IPV6} ]] && (
    pfw || prn "Ip6tables. Default deny firewall might need to be configured."
    pfw && prn "Ip6tables. Configuring default deny firewall policy."
    pfw && ip6tables -P INPUT DROP
    pfw && ip6tables -P OUTPUT DROP
    pfw && ip6tables -P FORWARD DROP
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.6.4.3.2; W=1; S=1; E=; SC=;  BD='Ensure IPv6 loopback traffic is configured'
lev && [[ ${FW} = "iptables" ]] && [[ ${IPV6} ]] && (
    pfw || prn "Ip6tables. Loopback traffic might need to be configured."
    pfw && prn "Ip6tables. Configuring loopback traffic."
    pfw && ip6tables -A INPUT  -i lo  -j ACCEPT
    pfw && ip6tables -A OUTPUT -o lo  -j ACCEPT
    pfw && ip6tables -A INPUT  -s ::1 -j DROP

)

NO=3.6.4.3.3; W=1; S=1; E=; SC=;  BD='Ensure IPv6 outbound and established connections are configured'
lev && [[ ${FW} = "iptables" ]] && [[ ${IPV6} ]] && (
    pfw || prn "Ip6tables. Outbound and established connections might need to be configured."
    pfw && prn "Ip6tables. Configuring outbound and established connections."
    pfw && ip6tables -A OUTPUT -p tcp  -m state --state NEW,ESTABLISHED -j ACCEPT
    pfw && ip6tables -A OUTPUT -p udp  -m state --state NEW,ESTABLISHED -j ACCEPT
    pfw && ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
    pfw && ip6tables -A INPUT  -p tcp  -m state --state ESTABLISHED     -j ACCEPT
    pfw && ip6tables -A INPUT  -p udp  -m state --state ESTABLISHED     -j ACCEPT
    pfw && ip6tables -A INPUT  -p icmp -m state --state ESTABLISHED     -j ACCEPT
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.6.4.3.4; W=1; S=1; E=; SC=N; BD='Ensure IPv6 firewall rules exist for all open ports'
lev && [[ ${FW} = "iptables" ]] && [[ ${IPV6} ]] && (
    pfw || prn "ip6tables. Firewall rules for all open ports might need to be configured."
    pfw && prn "ip6tables. Configuring firewall rules for all open ports."
# tcp
    while read PORT; do
        ip6tables -nL | grep ${PORT} | grep -q tcp
        case $? in
            0)  prn "TCP Port ${PORT} is already open in ip6tables." ;;
            *)  pfw || prn "ip6tables: Port ${PORT} might need to be opened."
                pfw && prw "ip6tables: Opening port ${PORT} ."
                case ${PORT} in
                    22) pfw && ip6tables -A INPUT --source ${INTNETWORK} -p tcp --dport 22 -m state --state NEW -j ACCEPT ;;
                    *)  pfw && ip6tables -A INPUT -p tcp --dport ${PORT} -m state --state NEW -j ACCEPT ;;
                esac ;;
        esac
    done < <(netstat -tnlp | grep "^tcp " | grep -v 127 | cut -d: -f2 | awk  '{print $1}')
# udp
    while read PORT; do
        ip6tables -nL | grep ${PORT} | grep -q udp
        case $? in
            0)  prn "UDP Port ${PORT} is already open in ip6tables." ;;
            *)  pfw || prn "ip6tables: Port ${PORT} might need to be opened."
                pfw && prw "ip6tables: Opening port ${PORT} ."
                pfw && ip6tables -A INPUT -p udp --dport ${PORT} -m state --state NEW -j ACCEPT ;;
        esac
    done < <(netstat -tnlp | grep "^udp " | grep -v 127 | cut -d: -f2 | awk  '{print $1}')
    pfw && ip6tables -A INPUT -j DROP
    pfw && iptables-save -c > /etc/iptables.rules
)

NO=3.7;       W=2; S=1; E=; SC=N; BD='Ensure wireless interfaces are disabled'
lev && (
    install_package network-manager
    upd && nmcli radio all off
)

NO=3.8;       W=2; S=2; E=; SC=N; BD='Disable IPv6'
lev && [[ -z ${IPV6} ]] && (
        update_conf /etc/default/grub 'GRUB_CMDLINE_LINUX="ipv6.disable=1"'
        update_grub
)

NO=4.1.1.1;   W=2; S=2; E=; SC=;  BD='Ensure auditd is installed'
lev && (
    install_package auditd
    install_package audispd-plugins 
)

NO=4.1.1.2;   W=2; S=2; E=; SC=;  BD='Ensure auditd service is enabled'
lev && (check_systemctl auditd)

NO=4.1.1.3;   W=2; S=2; E=; SC=;  BD='Ensure auditing for processes that start prior to auditd is enabled'
lev && (
    update_conf /etc/default/grub 'GRUB_CMDLINE_LINUX="audit=1"'
    update_grub
) 

NO=4.1.1.4;   W=2; S=2; E=; SC=;  BD='Ensure audit_backlog_limit is sufficient'
lev && (update_conf /etc/default/grub 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"')

NO=4.1.2.1;   W=2; S=2; E=; SC=;  BD='Ensure audit log storage size is configured'
lev && (update_conf /etc/audit/auditd.conf "max_log_file =" "max_log_file = ${MAXLOGFILE}")

NO=4.1.2.2;   W=2; S=2; E=; SC=;  BD='Ensure audit logs are not automatically deleted'
lev && (update_conf /etc/audit/auditd.conf "max_log_file_action" "max_log_file_action = keep_logs")

NO=4.1.2.3;   W=2; S=2; E=; SC=;  BD='Ensure system is disabled when audit logs are full'
lev && (
    update_conf /etc/audit/auditd.conf "space_left_action" "space_left_action = ${SPACELEFT}"
    update_conf /etc/audit/auditd.conf "action_mail_acct" "action_mail_acct = ${ACTIONMAILACCT}"
    update_conf /etc/audit/auditd.conf "admin_space_left_action" "admin_space_left_action = ${ADMINSPACELEFT}"
)

NO=4.1.3;     W=2; S=2; E=; SC=;  BD='Ensure events that modify date and time information are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F    arch=b64 -S adjtimex -S settimeofday -k time-change'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F    arch=b32 -S adjtimex -S settimeofday -S stime -k time-change'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F    arch=b64 -S clock_settime -k time-change'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F    arch=b32 -S clock_settime -k time-change'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/localtime    -p wa -k time-change'
)

NO=4.1.4;     W=2; S=2; E=; SC=;  BD='Ensure events that modify user/group information are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-w  /etc/group -p wa -k identity'
    update_conf /etc/audit/rules.d/audit.rules '-w  /etc/passwd -p wa -k identity'
    update_conf /etc/audit/rules.d/audit.rules '-w  /etc/gshadow -p wa -k identity'
    update_conf /etc/audit/rules.d/audit.rules '-w  /etc/shadow -p wa -k identity'
    update_conf /etc/audit/rules.d/audit.rules '-w  /etc/security/opasswd -p wa -k identity'
)    

NO=4.1.5;     W=2; S=2; E=; SC=;  BD='Ensure events that modify the systems network environment are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/issue -p wa -k system-locale'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/issue.net -p wa -k system-locale'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/hosts -p wa -k system-locale'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/network -p wa -k system-locale'
)

NO=4.1.6;     W=2; S=2; E=; SC=;  BD='Ensure events that modify the systems Mandatory Access Controls are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/apparmor/ -p wa -k MAC-policy'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/apparmor.d/ -p wa -k MAC-policy'
)

NO=4.1.7;     W=2; S=2; E=; SC=;  BD='Ensure login and logout events are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-w /var/log/faillog -p wa -k logins'
    update_conf /etc/audit/rules.d/audit.rules '-w /var/log/lastlog -p wa -k logins'
    update_conf /etc/audit/rules.d/audit.rules '-w /var/log/tallylog -p wa -k logins'
)

NO=4.1.8;     W=2; S=2; E=; SC=;  BD='Ensure session initiation information is collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-w /var/run/utmp -p wa -k session'
    update_conf /etc/audit/rules.d/audit.rules '-w /var/log/wtmp -p wa -k logins'
    update_conf /etc/audit/rules.d/audit.rules '-w /var/log/btmp -p wa -k logins'
)

NO=4.1.9;     W=2; S=2; E=; SC=;  BD='Ensure discretionary access control permission modification events are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod'
)

NO=4.1.10;    W=2; S=2; E=; SC=;  BD='Ensure unsuccessful unauthorized file access attempts are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access'
)

NO=4.1.11;    W=2; S=2; E=; SC=;  BD='Ensure use of privileged commands is collected'
lev && (
    while read FILE; do
        update_conf /etc/audit/rules.d/audit.rules "-a always,exit -F path=${FILE} -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"
    done < <(df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f \( -perm -4000 -o -perm -2000 \))
)

NO=4.1.12;    W=2; S=2; E=; SC=;  BD='Ensure successful file system mounts are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts'
)

NO=4.1.13;    W=2; S=2; E=; SC=;  BD='Ensure file deletion events by users are collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete'
)

NO=4.1.14;    W=2; S=2; E=; SC=;  BD='Ensure changes to system administration scope (sudoers) is collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/sudoers -p wa -k scope'
    update_conf /etc/audit/rules.d/audit.rules '-w /etc/sudoers.d/ -p wa -k scope'
)

NO=4.1.15;    W=2; S=2; E=; SC=;  BD='Ensure system administrator actions (sudolog) are collected'
lev && ( update_conf /etc/audit/rules.d/audit.rules '-w /var/log/sudo.log -p wa -k actions')

NO=4.1.16;    W=2; S=2; E=; SC=;  BD='Ensure kernel module loading and unloading is collected'
lev && (
    update_conf /etc/audit/rules.d/audit.rules '-w /sbin/insmod -p x -k modules'
    update_conf /etc/audit/rules.d/audit.rules '-w /sbin/rmmod -p x -k modules'
    update_conf /etc/audit/rules.d/audit.rules '-w /sbin/modprobe -p x -k modules'
    update_conf /etc/audit/rules.d/audit.rules '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules'
)

NO=4.1.17;    W=2; S=2; E=; SC=;  BD='Ensure the audit configuration is immutable'
lev && (
    # -e 2 must be last in the /etc/audit/rules.d/audit.rules file.
    tail -1  /etc/audit/rules.d/audit.rules | grep  '-e 2'
    case $? in
        0)  prn 'File /etc/audit/rules.d/audit.rules already has: "-e 2" in the last line.' ;;
        *)  grep -q '-e 2' /etc/audit/rules.d/audit.rules
            case $? in
                0)  upd || prw 'File /etc/audit/rules.d/audit.rules does not have "-e 2" in the last line. This needs to be deleted.'
                    upd && prw 'File /etc/audit/rules.d/audit.rules does not have "-e 2" in the last line. Deleting!.'
                    upd && sed -i "/^-e 2/ d " /etc/audit/rules.d/audit.rules
                    upd && update_conf /etc/audit/rules.d/audit.rules '-e 2' ;;
                *)  update_conf /etc/audit/rules.d/audit.rules '-e 2' ;;
            esac ;;
    esac
)

NO=4.2.1.1;   W=1; S=1; E=; SC=;  BD='Ensure rsyslog is installed'
lev &&  [[ ${SL} = "rsyslog" ]] && (
    remove_package syslog-ng
    install_package rsyslog
)

NO=4.2.1.2;   W=1; S=1; E=; SC=;  BD='Ensure rsyslog Service is enabled'
lev && [[ ${SL} = "rsyslog" ]] && (check_systemctl rsyslog)

NO=4.2.1.3;   W=1; S=1; E=; SC=N; BD='Ensure logging is configured'
lev && [[ ${SL} = "rsyslog" ]] && (
        update_conf /etc/rsyslog.d/50-default.conf '*.emerg                                  :omusrmsg:*'
        update_conf /etc/rsyslog.d/50-default.conf 'mail.*                                  -/var/log/mail'
        update_conf /etc/rsyslog.d/50-default.conf 'mail.info                               -/var/log/mail.info'
        update_conf /etc/rsyslog.d/50-default.conf 'mail.warning                            -/var/log/mail.warn'
        update_conf /etc/rsyslog.d/50-default.conf 'mail.err                                 /var/log/mail.err'
        update_conf /etc/rsyslog.d/50-default.conf 'news.crit                               -/var/log/news/news.crit'
        update_conf /etc/rsyslog.d/50-default.conf 'news.err                                -/var/log/news/news.err'
        update_conf /etc/rsyslog.d/50-default.conf 'news.notice                             -/var/log/news/news.notice'
        update_conf /etc/rsyslog.d/50-default.conf '*.=warning' '*.=warning;*.=err                       -/var/log/warn'
        update_conf /etc/rsyslog.d/50-default.conf '*.crit                                   /var/log/warn'
        update_conf /etc/rsyslog.d/50-default.conf '*.*;mail.none;news.none                 -/var/log/messages'
        update_conf /etc/rsyslog.d/50-default.conf 'local0,local1.*                         -/var/log/localmessages'
        update_conf /etc/rsyslog.d/50-default.conf 'local2,local3.*                         -/var/log/localmessages'
        update_conf /etc/rsyslog.d/50-default.conf 'local4,local5.*                         -/var/log/localmessages'
        update_conf /etc/rsyslog.d/50-default.conf 'local6,local7.*                         -/var/log/localmessages'
)

NO=4.2.1.4;   W=1; S=1; E=; SC=;  BD='Ensure rsyslog default file permissions configured'
lev && [[ ${SL} = "rsyslog" ]] && (update_conf /etc/rsyslog.conf '$FileCreateMode' '$FileCreateMode 0640')

NO=4.2.1.5;   W=1; S=1; E=; SC=;  BD='Ensure rsyslog is configured to send logs to a remote log host'
lev && [[ ${SL} = "rsyslog" ]] && [[ ! -z ${LOGHOST} ]] && (update_conf /etc/rsyslog.d/50-default.conf "*.* @@" "*.* @@${LOGHOST}")

NO=4.2.1.6;   W=1; S=1; E=; SC=N; BD='Ensure remote rsyslog messages are only accepted on designated log hosts'
lev
    # for hosts that are designated log hosts edit /etc/rsyslog.conf 
    #$ModLoad imtcp
    #$InProtocol 2putTCPServerRun 514
    ## for hosts that are not designated log hosts remove in /etc/rsyslog.conf
    #$ModLoad imtcp
    #$InputTCPServerRun 514

NO=4.2.1.7;   W=1; S=1; E=; SC=;  BD='Ensure syslog-ng service is enabled'
lev && [[ ${SL} = "syslog-ng" ]] && (
    remove_package rsyslog
    install_package syslog-ng
)

NO=4.2.1.8;   W=1; S=1; E=; SC=N; BD='Ensure syslog-ng logging is configured'
lev && [[ ${SL} = "syslog-ng" ]] && (update_file /etc/syslog-ng/conf.d/syslog-ng.conf root root 640)

NO=4.2.1.9;   W=1; S=1; E=; SC=;  BD='Ensure syslog-ng default file permissions configured'
    # edit /etc/syslog-ng/syslog-ng.conf
    #options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };

NO=4.2.1.10;  W=1; S=1; E=; SC=N; BD='Ensure syslog-ng is configured to send logs to a remote log host'
lev && [[ ${SL} = "syslog-ng" ]] && [[ ! -z ${LOGHOST} ]] && (
    [[ -z ${LOGTCP} ]] || update_conf /etc/syslog-ng/conf.d/syslog-ng.conf "destination logserver { tcp" "destination logserver { tcp(${LOGHOST} port(${LOGTCP})); };"
    [[ -z ${LOGUDP} ]] || update_conf /etc/syslog-ng/conf.d/syslog-ng.conf "destination logserver { udp" "destination logserver { udp(${LOGHOST} port(${LOGUDP})); };"
)

NO=4.2.1.11;  W=1; S=1; E=; SC=N; BD='Ensure remote syslog-ng messages are only accepted on designated log hosts'
lev # edit /etc/syslog-ng/syslog-ng.conf
    #source net{ tcp(); };
    #destination remote { file("/var/log/remote/${FULLHOST}-log"); };
    #log { source(net); destination(remote); };

NO=4.2.2.1;   W=1; S=1; E=; SC=;  BD='Ensure journald is configured to send logs to rsyslog'
lev && (update_conf /etc/systemd/journald.conf 'ForwardToSyslog' 'ForwardToSyslog=yes')

NO=4.2.2.2;   W=1; S=1; E=; SC=;  BD='Ensure journald is configured to compress large log files'
lev && (update_conf /etc/systemd/journald.conf 'Compress' 'Compress=yes')

NO=4.2.2.3;   W=1; S=1; E=; SC=;  BD='Ensure journald is configured to write logfiles to persistent disk'
lev && (update_conf /etc/systemd/journald.conf 'Storage' 'Storage=persistent')

NO=4.2.3;     W=1; S=1; E=; SC=;  BD='Ensure permissions on all logfiles are configured'
lev && (
    [[ $(find /var/log -type f -perm /g=w,g=x,o=r,o=w,o=x | wc -l) -eq 0 ]] || {
        upd || prw "Some /var/log files have group w,x or other r,w,x permissions. This needs to be fixed."
        upd && prw "Some /var/log files have group w,x or other r,w,x permissions. Fixing!"
        upd && find /var/log -type f -exec chmod g-wx,o-rwx {} \; 
    }
    err  || prn "No /var/log files have group r,w or other r,w,x permissions."
    E=
    [[ $(find /var/log -type d -perm /g=w,o=r,o=w,o=x | wc -l) -eq 0 ]] || {
        upd || prw "Some /var/log folders have group w or other r,w,x permissions. This needs to be fixed."
        upd && prw "Some /var/log folders have group w or other r,w,x permissions. Fixing!"
        upd && find /var/log -type d -exec chmod g-w,o-rwx {} \;
    }
    err  || prn "No /var/log folders have group w or other r,w,x permissions."
)

NO=4.3;       W=1; S=1; E=; SC=N; BD='Ensure logrotate is configured'
lev && (update_conf /etc/logrotate.conf "maxage" "maxage ${MAXLOGAGE}")

NO=4.4;       W=1; S=1; E=; SC=;  BD='Ensure logrotate assigns appropriate permissions'
lev && (update_conf /etc/logrotate.conf 'create' 'create 0640 root utmp')

NO=5.1.1;     W=1; S=1; E=; SC=;  BD='Ensure cron daemon is enabled'
lev && (check_systemctl cron)

NO=5.1.2;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/crontab are configured'
lev && (update_file /etc/crontab root root 600)

NO=5.1.3;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/cron.hourly are configured'
lev && (update_file /etc/cron.hourly root root 700)

NO=5.1.4;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/cron.daily are configured'
lev && (update_file /etc/cron.daily root root 700)

NO=5.1.5;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/cron.weekly are configured'
lev && (update_file /etc/cron.weekly root root 700)

NO=5.1.6;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/cron.monthly are configured'
lev && (update_file /etc/cron.monthly root root 700)

NO=5.1.7;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/cron.d are configured'
lev && (update_file /etc/cron.d root root 700)

NO=5.1.8;     W=1; S=1; E=; SC=;  BD='Ensure at/cron is restricted to authorized users'
lev && (
    delete_file /etc/cron.deny
    delete_file /etc/at.deny
    update_file /etc/at.allow   root root 600 '# Created by Cisecurity remediation script'
    update_file /etc/cron.allow root root 600 '# Created by Cisecurity remediation script'
)

NO=5.2.1;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/ssh/sshd_config are configured'
lev && [[ ${SSSHD} ]] && (update_file /etc/ssh/sshd_config root root 600)

NO=5.2.2;     W=1; S=1; E=; SC=;  BD='Ensure permissions on SSH private host key files are configured'
lev && [[ ${SSSHD} ]] && (
    for KEY in /etc/ssh/ssh_host_*_key; do 
        update_file ${KEY} root root 600
    done 
)

NO=5.2.3;     W=1; S=1; E=; SC=;  BD='Ensure permissions on SSH public host key files are configured'
lev && [[ ${SSSHD} ]] && (
    for KEY in /etc/ssh/ssh_host_*_key.pub; do 
        update_file ${KEY} root root 644
    done 
)

NO=5.2.4;     W=1; S=1; E=; SC=;  BD='Ensure SSH Protocol is not set to 1'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'Protocol' 'Protocol 2')

NO=5.2.5;     W=1; S=1; E=; SC=;  BD='Ensure SSH LogLevel is appropriate'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'LogLevel' 'LogLevel INFO')

NO=5.2.6;     W=1; S=1; E=; SC=;  BD='Ensure SSH X11 forwarding is disabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'X11Forwarding' 'X11Forwarding no')

NO=5.2.7;     W=1; S=1; E=; SC=;  BD='Ensure SSH MaxAuthTries is set to 4 or less'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'MaxAuthTries' 'MaxAuthTries 4')

NO=5.2.8;     W=1; S=1; E=; SC=;  BD='Ensure SSH IgnoreRhosts is enabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'IgnoreRhosts' 'IgnoreRhosts yes')

NO=5.2.9;     W=1; S=1; E=; SC=;  BD='Ensure SSH HostbasedAuthentication is disabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'HostbasedAuthentication' 'HostbasedAuthentication no')

NO=5.2.10;    W=1; S=1; E=; SC=;  BD='Ensure SSH root login is disabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'PermitRootLogin' 'PermitRootLogin no')

NO=5.2.11;    W=1; S=1; E=; SC=;  BD='Ensure SSH PermitEmptyPasswords is disabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'PermitEmptyPasswords' 'PermitEmptyPasswords no')

NO=5.2.12;    W=1; S=1; E=; SC=;  BD='Ensure SSH PermitUserEnvironment is disabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'PermitUserEnvironment' 'PermitUserEnvironment no')

NO=5.2.13;    W=1; S=1; E=; SC=;  BD='Ensure only strong Ciphers are used'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'Ciphers' 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr')

NO=5.2.14;    W=1; S=1; E=; SC=;  BD='Ensure only strong MAC algorithms are used'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'MACs' 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256')

NO=5.2.15;    W=1; S=1; E=; SC=;  BD='Ensure only strong Key Exchange algorithms are used'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'KexAlgorithms' 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256') 

NO=5.2.16;    W=1; S=1; E=; SC=;  BD='Ensure SSH Idle Timeout Interval is configured'
lev && [[ ${SSSHD} ]] && (
    update_conf /etc/ssh/sshd_config "ClientAliveInterval" "ClientAliveInterval ${SSHTMOUT}"
    update_conf /etc/ssh/sshd_config 'ClientAliveCountMax' "ClientAliveCountMax ${SSHCOMAX}"
)

NO=5.2.17;    W=1; S=1; E=; SC=;  BD='Ensure SSH LoginGraceTime is set to one minute or less'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'LoginGraceTime' 'LoginGraceTime 60')

NO=5.2.18;    W=1; S=1; E=; SC=;  BD='Ensure SSH access is limited'
lev && [[ ${SSSHD} ]] && [[ ${SUDOUSR} ]] && (update_conf /etc/ssh/sshd_config 'AllowUsers' "AllowUsers ${SUDOUSR}")

NO=5.2.19;    W=1; S=1; E=; SC=;  BD='Ensure SSH warning banner is configured'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'Banner /etc/issue.net' 'Banner /etc/issue.net')

NO=5.2.20;    W=1; S=1; E=; SC=;  BD='Ensure SSH PAM is enabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'UsePAM' 'UsePAM yes')

NO=5.2.21;    W=1; S=1; E=; SC=;  BD='Ensure SSH AllowTcpForwarding is disabled'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'AllowTcpForwarding' 'AllowTcpForwarding no')

NO=5.2.22;    W=1; S=1; E=; SC=;  BD='Ensure SSH MaxStartups is configured'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'MaxStartups' 'MaxStartups 10:30:60')

NO=5.2.23;    W=1; S=1; E=; SC=;  BD='Ensure SSH MaxSessions is set to 4 or less'
lev && [[ ${SSSHD} ]] && (update_conf /etc/ssh/sshd_config 'MaxSessions' "MaxSessions ${SSHMAXSS}")

NO=5.3.1;     W=1; S=1; E=; SC=;  BD='Ensure password creation requirements are configured'
lev && (
    install_package libpam-pwquality
    update_conf /etc/pam.d/common-password "password	requisite			pam_pwquality" "password	requisite			pam_pwquality.so retry=${PAMRETRY}"
    update_conf /etc/security/pwquality.conf "minlen"  "minlen  = ${PAMMINLEN}"
    update_conf /etc/security/pwquality.conf "dcredit" "dcredit = ${PAMDCREDIT}"
    update_conf /etc/security/pwquality.conf "ucredit" "ucredit = ${PAMUCREDIT}"
    update_conf /etc/security/pwquality.conf "ocredit" "ocredit = ${PAMOCREDIT}"
    update_conf /etc/security/pwquality.conf "lcredit" "lcredit = ${PAMLCREDIT}"
)

NO=5.3.2;     W=1; S=1; E=; SC=;  BD='Ensure lockout for failed password attempts is configured'
lev && (
    update_conf /etc/pam.d/common-auth "auth required pam_tally2" "auth required pam_tally2.so onerr=fail audit silent deny=${PAMDENY} unlock_time=${PAMUNLOCK}"
    update_conf /etc/pam.d/common-account 'account	requisite			pam_deny.so'
    update_conf /etc/pam.d/common-account 'account	required			pam_tally2.so'
)

NO=5.3.3;     W=1; S=1; E=; SC=;  BD='Ensure password reuse is limited'
lev && (update_conf /etc/pam.d/common-password "password required pam_pwhistory" "password required pam_pwhistory.so remember=${PAMHISTORY}")

NO=5.3.4;     W=1; S=1; E=; SC=;  BD='Ensure password hashing algorithm is SHA-512'
lev && (
    grep "^password" /etc/pam.d/common-password | grep -q ${PAMENCRYPT}
    (($? != 0)) && prw "Password encryption is not set to ${PAMENCRYPT}. Update manually in /etc/pam.d/common-password."
    err         || prn "Password encryption is already set to ${PAMENCRYPT}."
)

NO=5.4.1.1;   W=1; S=1; E=; SC=;  BD='Ensure password expiration is 365 days or less'
lev && (
    update_conf /etc/login.defs "PASS_MAX_DAYS" "PASS_MAX_DAYS ${PASSMAXDAYS}"
    update_chage 5 ${PASSMAXDAYS}
)

NO=5.4.1.2;   W=1; S=1; E=; SC=;  BD='Ensure minimum days between password changes is configured'
lev && (
    update_conf /etc/login.defs "PASS_MIN_DAYS" "PASS_MIN_DAYS ${PASSMINDAYS}"
    update_chage 4 ${PASSMINDAYS}
)

NO=5.4.1.3;   W=1; S=1; E=; SC=;  BD='Ensure password expiration warning days is 7 or more'
lev && (
    update_conf /etc/login.defs "PASS_WARN_AGE" "PASS_WARN_AGE ${PASSWARNDAYS}"
    update_chage 6 ${PASSWARNDAYS}
)

NO=5.4.1.4;   W=1; S=1; E=; SC=;  BD='Ensure inactive password lock is 30 days or less'
lev && (
    upd && useradd -D -f ${PASSINACTIVE}
    update_chage 7 ${PASSINACTIVE}
)

NO=5.4.1.5;   W=1; S=1; E=; SC=;  BD='Ensure all users last password change date is in the past'
lev && (
    TODAY=$(date +"%Y%m%d")
    update_chage 0 ${TODAY}
)

NO=5.4.2;     W=1; S=1; E=; SC=;  BD='Ensure system accounts are secured'
lev && (
    while read USR; do
        upd || prw "System account ${USR} has shell $(grep ^${USR} /etc/passwd | awk -F: '{print $7}'). It needs to be changed to $(which nologin)." 
        upd && prw "Changing system account ${USR} shell from $(grep ^${USR} /etc/passwd | awk -F: '{print $7}') to $(which nologin)."
        upd && usermod -s $(which nologin) ${USR}
    done < <(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd)
    err     || prn "All system accounts except root,sync,shutdown,halt have $(which nologin) shell." 
    E=
    while read USR; do
        upd || prw "System account ${USR} needs to be locked." 
        upd && prw "Locking system account ${USR}." 
        upd && usermod -L ${USR}
        exit 5
    done < <(awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}')
    err     || prn "All system accounts except root are locked."
)

NO=5.4.3;     W=1; S=1; E=; SC=;  BD='Ensure default group for the root account is GID 0'
lev && (
    if [[ $(grep "^root:" /etc/passwd | cut -d: -f4) != "0" ]]; then
        upd || prw "Root account does not have group ID 0. Please investigate." 
        upd && prw "Setting root account group ID to 0. Please investigate why group ID is not set to 0." 
        upd && usermod -g 0 root
    fi
    err     || prn "Root account has group ID 0."
)

NO=5.4.4;     W=1; S=1; E=; SC=;  BD='Ensure default user umask is 027 or more restrictive'
lev && (
    #update_conf /etc/profile 'umask' 'umask 027'
    update_conf /etc/bash.bashrc 'umask' 'umask 027'
    update_conf /etc/profile.d/apps-bin-path.sh 'umask' 'umask 027'
)

NO=5.4.5;     W=1; S=1; E=; SC=;  BD='Ensure default user shell timeout is 900 seconds or less'
lev && (
    #update_conf /etc/profile     "readonly TMOUT" "readonly TMOUT=${CISTMOUT} ; export TMOUT"
    update_conf /etc/bash.bashrc "readonly TMOUT" "readonly TMOUT=${CISTMOUT} ; export TMOUT"
)

NO=5.5;       W=1; S=1; E=; SC=N; BD='Ensure root login is restricted to system console'
lev && (
    head -1 /etc/securetty  | grep -q "^console"
        (($? != 0)) && {
            upd && [[ -n "${ROOTLOGIN}" ]] && > /etc/securetty
            for CONSOLE in ${ROOTLOGIN}
            do
                upd || prw "File /etc/securetty needs to be updated with ${CONSOLE}." 
                upd && prw "Updating /etc/securetty with ${CONSOLE}." 
                upd && echo ${CONSOLE} >> /etc/securetty
            done 
        }
        err || prn "File /etc/securetty is already updated with ${ROOTLOGIN}."
)
#ken

NO=5.6;       W=1; S=1; E=; SC=;  BD='Ensure access to the su command is restricted'
lev && (
    update_conf /etc/pam.d/su "auth required            pam_wheel.so" "auth required            pam_wheel.so    use_uid group=${SUGROUP}"
    grep -q ^${SUGROUP} /etc/group
    case $? in
        0)  prn "Group ${SUGROUP} already exists in /etc/group."
            grep ${SUGROUP} /etc/group | cut -d: -f4 | grep -i '[a-z]'
            case $? in
                0)  prw "Group ${SUGROUP} contains user accounts. It should be empty." ;;
                *)  prn "Group ${SUGROUP} does not contains any users." ;;
            esac ;;
        *)  upd || prw "Group ${SUGROUP} needs to be added to /etc/group."
            upd && prw "Adding Group ${SUGROUP} to /etc/group."
            upd && groupadd ${SUGROUP} ;;
    esac
)

NO=6.1.1;     W=2; S=2; E=; SC=N; BD='Audit system file permissions'
lev && (
    while read PKG ; do
        dpkg --verify ${PKG} | grep -v '??5?????? c' >> ${TMP1}
    done < <(apt list --installed 2> /dev/null | cut -d"/" -f1 | grep -v Listing)
    if  [[ -s ${TMP1} ]]; then
        prw "The following packages have been modified. Please check."
        cat ${TMP1} >> ${CISWARNLOG}
    fi
    err || prn "No packages have been modified." 
)

NO=6.1.2;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/passwd are configured'
lev && (update_file /etc/passwd root root 644)

NO=6.1.3;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/gshadow- are configured'
lev && (update_file /etc/gshadow- root shadow 640)

NO=6.1.4;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/shadow are configured'
lev && (update_file /etc/shadow root shadow 640)

NO=6.1.5;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/group are configured'
lev && (update_file /etc/group root root 644)

NO=6.1.6;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/passwd- are configured'
lev && (update_file /etc/passwd- root root 600)

NO=6.1.7;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/shadow- are configured'
lev && (update_file /etc/shadow- root shadow 600)

NO=6.1.8;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/group- are configured'
lev && (update_file /etc/group- root root 644)

NO=6.1.9;     W=1; S=1; E=; SC=;  BD='Ensure permissions on /etc/gshadow are configured'
lev && (update_file /etc/gshadow root shadow 640)

NO=6.1.10;    W=1; S=1; E=; SC=;  BD='Ensure no world writable files exist'
lev && (
    while read FILE; do 
        upd || prw "File ${FILE} is world-writable. This needs to be fixed." 
        upd && prw "File ${FILE} is world-writable. Fixing permissions." 
        upd && chmod o-w ${FILE}
    done < <(df --local -P | grep -v "/run" | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002)
    err || prn "No world-writable files found." 
)

NO=6.1.11;    W=1; S=1; E=; SC=;  BD='Ensure no unowned files or directories exist'
lev && (
    while read FILE; do 
        upd || prw "File ${FILE} is unowned. This needs to be changed to $(stat -c %U $(dirname ${FILE}))." 
        upd && prw "File ${FILE} is unowned. Changing user to $(stat -c %U $(dirname ${FILE}))."
        upd && chown -h $(stat -c %U $(dirname ${FILE})) ${FILE} 
    done < <(df --local -P | grep -v "/run" | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)
    err || prn "No unowned files found." 
)

NO=6.1.12;    W=1; S=1; E=; SC=;  BD='Ensure no ungrouped files or directories exist'
lev && (
    while read FILE; do 
        upd || prw "File ${FILE} is ungrouped. This needs to be changed to $(stat -c %G $(dirname ${FILE}))." 
        upd && prw "File ${FILE} is ungrouped. Changing user to $(stat -c %G $(dirname ${FILE}))."
        upd && chgrp -h $(stat -c %G $(dirname ${FILE})) ${FILE} 
    done < <(df --local -P | grep -v "/run" | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup)
    err || prn "No ungrouped files found." 
)

NO=6.1.13;    W=1; S=1; E=; SC=N; BD='Audit SUID executables'
lev && (
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null | sort >${TMP2}
    grep "##SUID##" ${CISRC} | cut -d" " -f2 | sort > ${TMP1}
    diff ${TMP1} ${TMP2} > /dev/null 2>&1
    case $? in
        0)  prn "No extra suid files found." ;;
        *)  prw "Unknown suid files found."
            diff ${TMP1} ${TMP2} >> ${CISWARNLOG}
            upd && (
                read -p "Do you want to reset SUID files baseline in ${CISRC} N/y: " ANS
                case ${ANS} in
                    [yY]*)  sed -i "/^##SUID##/ d " ${CISRC}
                            while IFS= read -r FILE; do
                                printf '##SUID## %s\n' "${FILE}" >> ${CISRC}
                            done < <(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null | sort) ;;
                esac 
            ) ;;
    esac
)

NO=6.1.14;    W=1; S=1; E=; SC=N; BD='Audit SGID executables'
lev && (
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null | sort >${TMP2}
    grep "##SGID##" ${CISRC} | cut -d" " -f2 | sort > ${TMP1}
    diff ${TMP1} ${TMP2} > /dev/null 2>&1
    case $? in
        0)  prn "No extra sgid files found." ;;
        *)  prw "Unknown sgid files found."
            diff ${TMP1} ${TMP2} >> ${CISWARNLOG}
            upd && (
                read -p "Do you want to reset SGID files baseline in ${CISRC} N/y: " ANS
                case ${ANS} in
                    [yY]*)  sed -i "/^##SGID##/ d " ${CISRC}
                            while IFS= read -r FILE; do
                                printf '##SGID## %s\n' "${FILE}" >> ${CISRC}
                            done < <(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null | sort) ;;
                esac
            ) ;;
    esac
)

NO=6.2.1;     W=1; S=1; E=; SC=;  BD='Ensure password fields are not empty'
lev && (
    while read USR; do 
        upd || prw "User ${USR} has no password. This account needs to be locked."
        upd && prw "User ${USR} has no password. Locking this account."
        upd && usermod -L ${USR}
    done < <(awk -F: '($2 == "" ) {print $1}' /etc/shadow)
    err || prn "No logins without passwords."
)

NO=6.2.2;     W=1; S=1; E=; SC=;  BD='Ensure no legacy "+" entries exist in /etc/passwd'
lev && (
    grep -q '^\+:' /etc/passwd
    (($? == 0)) && prw "File /etc/passwd contains legacy +. Fix manually."
    err      || prn "File /etc/passwd does not contain legacy +."
)

NO=6.2.3;     W=1; S=1; E=; SC=;  BD='Ensure all users home directories exist'
lev && (
    while read USR DIR; do
        if  [[ ! -d ${DIR} ]]; then
            upd || prw "The home directory (${DIR} of user ${USR} does not exist. This needs to be fixed."
            upd && prw "The home directory (${DIR} of user ${USR} does not exist. Fixing."
            upd && mkdir -p -m 750 ${DIR}
            upd && chown ${USR} ${DIR}
            upd && chgrp $(id -g ${USR}) ${DIR}
        fi
    done < <(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }')
    err  || prn "All standard users and root have a home directory."
)

NO=6.2.4;     W=1; S=1; E=; SC=;  BD='Ensure no legacy "+" entries exist in /etc/shadow'
lev && (
    grep -q '^\+:' /etc/shadow
    (($? == 0)) && prw "File /etc/shadow contains legacy +. Fix manually."
    err      || prn "File /etc/shadow does not contain legacy +."
)

NO=6.2.5;     W=1; S=1; E=; SC=;  BD='Ensure no legacy "+" entries exist in /etc/group'
lev && (
    grep -q '^\+:' /etc/group
    (($? == 0)) && prw "File /etc/group contains legacy +. Fix manually."
    err      || prn "File /etc/group does not contain legacy +."
)

NO=6.2.6;     W=1; S=1; E=; SC=;  BD='Ensure root is the only UID 0 account'
lev && (
    while read USR; do
        prw "User ${USR} has UID 0. Fix manually."
    done < <(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v root)
    err || prn "No extra UID 0 users found." 
)

NO=6.2.7;     W=1; S=1; E=; SC=;  BD='Ensure root PATH Integrity'
lev && (
    (echo $PATH | grep -q ::) && prw "Empty Directory in ${PATH}"
    (echo $PATH | grep -q :$) && prw "Trailing : in ${PATH}"
    for DIR in $(echo $PATH | tr ":" " "); do
        [[ ${DIR} = "." ]] && prw "PATH contains ."
        if [[ -d ${DIR} ]]; then
            (ls -ldH ${DIR} | cut -c6 | grep -q "-")           || prw "Group Write permission set on directory ${DIR}"
            (ls -ldH ${DIR} | cut -c9 | grep -q "-")           || prw "Other Write permission set on directory ${DIR}"
            (ls -ldH ${DIR} | awk '{print $3}' | grep -q root) || prw "Directory ${DIR} is not owned by root."
        else
            prw "Path ${DIR} is not a directory."
        fi
    done
    err || prn "PATH integrity is correct."
)

NO=6.2.8;     W=1; S=1; E=; SC=;  BD='Ensure users home directories permissions are 750 or more restrictive'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory (${DIR}) of user ${USR} does not exist." 
        else 
            PERM=$(ls -ld ${DIR} | cut -f1 -d" ") 
            if  [[ $(echo ${PERM} | cut -c1) = "l" ]]; then
                prw "${DIR} is a symbolic link. Fix manually." 
            else
                if  [[ $(echo ${PERM} | cut -c6) != "-" ]]; then 
                    upd || prw "Group Write permission set on the home directory (${DIR}) of user ${USR}. This needs to be fixed." 
                    upd && prw "Group Write permission set on the home directory (${DIR}) of user ${USR}. Fixing." 
                    upd && chmod g-w ${DIR}
                fi 
                if  [[ $(echo ${PERM} | cut -c8) != "-" ]]; then 
                    upd || prw "Other Read permission set on the home directory (${DIR}) of user ${USR}. This needs to be fixed." 
                    upd && prw "Other Read permission set on the home directory (${DIR}) of user ${USR}. Fixing." 
                    upd && chmod o-r ${DIR}
                fi 
                if  [[ $(echo ${PERM} | cut -c9) != "-" ]]; then 
                    upd || prw "Other Write permission set on the home directory (${DIR}) of user ${USR}. This needs to be fixed." 
                    upd && prw "Other Write permission set on the home directory (${DIR}) of user ${USR}. Fixing." 
                    upd && chmod o-w ${DIR}
                fi 
                if  [[ $(echo ${PERM} | cut -c10) != "-" ]]; then 
                    upd || prw "Other Execute permission set on the home directory (${DIR}) of user ${USR}. This needs to be fixed." 
                    upd && prw "Other Execute permission set on the home directory (${DIR}) of user ${USR}. Fixing." 
                    upd && chmod o-x ${DIR}
                fi 
            fi 
        fi
    done < <(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "All home directories have correct permissions (750)."
)

NO=6.2.9;     W=1; S=1; E=; SC=;  BD='Ensure users own their home directories'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory (${DIR}) of user ${USR} does not exist." 
        else 
            OWNER=$(stat -L -c "%U" "${DIR}") 
            if [[ ${OWNER} != ${USR} ]]; then 
                prw "The home directory (${DIR}) of user ${USR} is owned by ${OWNER}." 
            fi 
        fi 
    done < <(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "All users own their home directories."
)

NO=6.2.10;    W=1; S=1; E=; SC=;  BD='Ensure users dot files are not group or world writable'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory (${DIR}) of user ${USR} does not exist." 
        else 
            for FILE in ${DIR}/.[A-Za-z0-9]*; do 
                if [[ ! -h "$FILE" ]] && [[ -f "$FILE" ]]; then 
                    PERM=$(ls -ld ${FILE} | cut -f1 -d" ") 
                    if  [[ $(echo ${PERM} | cut -c1) = "l" ]]; then
                        prw "File ${FILE} is a symbolic link. Fix manually." 
                    else
                        if  [[ $(echo ${PERM} | cut -c6) != "-" ]]; then 
                            upd || prw "Group Write permission set on file ${FILE}. This needs to be fixed." 
                            upd && prw "Group Write permission set on file ${FILE}. Fixing." 
                            upd && chmod g-w ${FILE}
                        fi 
                        if  [[ $(echo ${PERM} | cut -c9) != "-" ]]; then 
                            upd || prw "Other Write permission set on file ${FILE}. This needs to be fixed." 
                            upd && prw "Other Write permission set on file ${FILE}. Fixing." 
                            upd && chmod o-w ${FILE}
                        fi 
                    fi 
                fi 
            done 
        fi
    done < <(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "All users dot files are not group or world writable."

)

NO=6.2.11;    W=1; S=1; E=; SC=;  BD='Ensure no users have .forward files'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory (${DIR}) of user ${USR} does not exist." 
        else 
            if [[ ! -h "${DIR}/.forward" && -f "${DIR}/.forward" ]]; then 
                prw "User ${USR} has a .forward file ${DIR}. Fix manually." 
            fi 
        fi 
    done < <(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "No users have .forward files."
)

NO=6.2.12;    W=1; S=1; E=; SC=;  BD='Ensure no users have .netrc files'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory (${DIR}) of user ${USR} does not exist." 
        else 
            if [[ -f "${DIR}/.netrc" ]]; then 
                prw "User ${USR} has a .netrc file in ${DIR}. Fix manually." 
            fi 
        fi 
    done < <(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "No users have .netrc files."
)

NO=6.2.13;    W=1; S=1; E=; SC=;  BD='Ensure users .netrc Files are not group or world accessible'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory (${DIR}) of user ${USR} does not exist." 
        else 
            if [[ -f "${DIR}/.netrc" ]]; then
                PERM=$(stat -L -c %a ${DIR}/.netrc)
                if [[ ${PERM} != "600" ]]; then
                    upd || prw "The .netrc file permissions for user ${USR} are ${PERM} but should be 600. This needs to be fixed."
                    upd && prw "The .netrc file permissions for user ${USR} are ${PERM} but should be 600. Fixing."
                    upd && chmod 600 "${DIR}/.netrc"
                fi
            fi
        fi
    done < <(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "No users have group or world accessible .netrc files."
)

NO=6.2.14;    W=1; S=1; E=; SC=;  BD='Ensure no users have .rhosts files'
lev && (
    while read USR DIR; do 
        if [[ ! -d ${DIR} ]]; then 
            prw "The home directory of user ${USR} does not exist." 
        else 
            if [[ ! -h ${DIR}/.rhosts ]] && [[ -f "${DIR}/.rhosts" ]]; then 
                prw "${USR} has .rhosts file in ${DIR}" 
            fi 
        fi 
    done < <(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }') 
    err || prn "No users have .rhosts files."
)

NO=6.2.15;    W=1; S=1; E=; SC=;  BD='Ensure all groups in /etc/passwd exist in /etc/group'
lev && (
    for GROUP in $(cut -s -d: -f4 /etc/passwd | sort -u ); do 
        grep -q -P "^.*?:[^:]*:${GROUP}:" /etc/group 
        if [[ $? -ne 0 ]]; then 
            prw "Group ${GROUP} is referenced by /etc/passwd but does not exist in /etc/group." 
        fi 
    done
    err || prn "All groups in /etc/passwd exist in /etc/group."
)

NO=6.2.16;    W=1; S=1; E=; SC=;  BD='Ensure no duplicate UIDs exist'
lev && (
    while read USR ; do
        prw "Duplicate UID: ${USR} in /etc/passwd. Fix manually."
    done < <(cut -d: -f3 /etc/passwd | sort | uniq -d)
    err || prn "No users have duplicate UID."
)

NO=6.2.17;    W=1; S=1; E=; SC=;  BD='Ensure no duplicate GIDs exist'
lev && (
    while read GROUP ; do
        prw "Duplicate GID: ${GROUP} in /etc/group. Fix manually."
    done < <(cut -d: -f3 /etc/group | sort | uniq -d)
    err || prn "No users have duplicate GID."
)

NO=6.2.18;    W=1; S=1; E=; SC=;  BD='Ensure no duplicate user names exist'
lev && (
    while read USR ; do
        prw "Duplicate login name: ${USR} in /etc/passwd. Fix manually."
    done < <(cut -d: -f1 /etc/passwd | sort | uniq -d)
    err || prn "No login names are duplicated."
)

NO=6.2.19;    W=1; S=1; E=; SC=;  BD='Ensure no duplicate group names exist'
lev && (
    while read GROUP ; do
        prw "Duplicate group name: ${GROUP} in /etc/group. Fix manually."
    done < <(cut -d: -f1 /etc/group | sort | uniq -d)
    err || prn "No group names are duplicated."
)

NO=6.2.20;    W=1; S=1; E=; SC=;  BD='Ensure shadow group is empty'
lev && (
    while read USR; do
        prw "User ${USR} has shadow group in /etc/passwd. This needs to be fixed manually."
    done < <(awk -F: '($4 == 42) {print $1}' /etc/passwd)
    err || prn "No users belong to the shadow group." 
    E=
    while read USR; do
        upd || prw "Shadow group account has user account: ${USR}. This needs to be fixed."
        upd && prw "Removing user accounts ${USR} from shadow group account."
        upd && update_conf /etc/group "shadow:x:42:"
    done < <(awk -F: '($1 == "shadow") {print $4}' /etc/group | grep "[a-z,A-Z,0-9]")
    err || prn "Shadow group account does not have any users." 
)

NO=9.9.9.9;    W=3; S=3; E=; SC=;  BD='Extra personal settings'
lev && (
    update_conf /etc/bash.bashrc 'export HISTTIMEFORMAT' 'export HISTTIMEFORMAT="%F %T "'
    update_conf /etc/bash.bashrc 'export HISTCONTROL' 'export HISTCONTROL==ignoreboth:erasedups'
    update_conf /etc/bash.bashrc 'set -o vi'
    update_conf /etc/vim/vimrc 'set showcmd'
    update_conf /etc/vim/vimrc 'set showmatch'
    update_conf /etc/vim/vimrc 'set ignorecase'
    update_conf /etc/vim/vimrc 'set incsearch'
    update_conf /etc/vim/vimrc 'set tabstop=4'
    update_conf /etc/vim/vimrc 'set softtabstop=0'
    update_conf /etc/vim/vimrc 'set expandtab'
    update_conf /etc/vim/vimrc 'set shiftwidth=4'
    update_conf /etc/vim/vimrc 'set smarttab'
    update_conf /etc/sysctl.d/local.conf 'net.core.default_qdisc=fq'              #BBR
    update_conf /etc/sysctl.d/local.conf 'net.ipv4.tcp_congestion_control=bbr'    #BBR
)

qte || (
    echo -e "\n\n\n\n######################################"

    if [[ -s "${CISWARNLOG}" ]]; then
        echo -e "\nWarning messages found in ${CISWARNLOG}\n" 
        read -p 'Show warning log file? Y/n: ' ANS
        case ${ANS} in
            [nN]) : ;;
            *)    less ${CISWARNLOG} ;;
        esac
        upd && echo -e "\nReboot server, fix errors and rerun script." 
    else
        echo -e "\nNo warning messages found in ${CISWARNLOG}." 
        echo -e "\nSystem is hardened." 
    fi
    echo -e "\n######################################"
)
