# System Hardening

## Limit Node Access
- command to list id of user
  ```
  id
  ```
- command to list information of existing user
  ```
  cat /etc/passwd | grep mail
  ```
- command to change password of user
  ```
  passwd david
  ```
- command to delete user name ray
  ```
  deluser ray
  ```
- command to delete group
  ```
  delgroup devs
  ```
- command to modify shell for user
  ```
  usermod himanshi -s /usr/sbin/nologin
  ```
- Create a user named sam on the controlplane host. The user's home directory must be /opt/sam. Login shell must be /bin/bash and uid must be 2328. Make sam a member of the admin group.
  ```
  useradd sam -d /opt/sam -s /bin/bash -u 2328 -G admin
  ```

 ## SSH hardening with sudo

  - default scp port 22
  - to provide private key while ssh login we can use ssh -i command to pass private key
  - different authentication method is available to login to ssh  such as via public key authentication, password based authentication and None
  - to enable passwordless authentication to node01(Create a user named jim on node01 host and configure password-less ssh access from controlplane host (from user root) to node01 host (to user jim).)
    ```
    ssh into node01 host from controlplane host
    ssh node01

    Create user jim on node01 host
    adduser jim (set any password you like)

    Return back to controlplane host and copy ssh public key
    ssh-copy-id -i ~/.ssh/id_rsa.pub jim@node01

    Test ssh access from controlplane host
    ssh jim@node01
    ```
- to make jim a sudo user
    On node01 host, open /etc/sudoers file using any editor like vi and add an entry for user jim and forcefully save the file.
    ```
     jim    ALL=(ALL:ALL) ALL
   ```
- to make jim to run sudo without entering password
  ```
  jim  ALL=(ALL) NOPASSWD:ALL
  ```
- to make user a member of admin group without changing sudoers file
  ```
  usermod rob -G admin
  ```
- There is some issue with sudo on node01 host, as user rob is not able to run sudo commands, investigate and fix this issue.
  Password for user rob that we set in the previous question: jid345kjf
  ```
  node01 ~ ➜  sudo su -
  node01 ~ ➜  su rob
  \[\]node01\[\] \[\]~\[\] \[\]➜\[\]  sudo apt-get update
   [sudo] password for rob: 
   rob is not in the sudoers file.  This incident will be reported.
   sudo visudo
   %admin ALL=(ALL) ALL
   ```
  
- to disable ssh root login and disable password authentication for ssh on node01 host,default location of sshd config /etc/ssh/sshd_config
  
  ```
    PermitRootLogin No
    PasswordAuthentication No
  ```
- restart sshd service
  
## Identify open ports, remove packages services

-  commands to list all installed packages on an ubuntu system
  ```
   apt list --installed
  ```
- commands to list only active services on a system, here systemctl list-units will already listing active units only.
  ```
    systemctl list-units --type service
  ```
- command to list the kernel modules currently loaded on a system?
  ```
    lsmod
  ```
- On the controlplane host, we have nginx service running which isn't needed on that system. Stop the nginx service and remove its service unit file. Make sure not to remove nginx package from the system.
  ```
    systemctl list-units --all | grep nginx
    systemctl stop nginx
    systemctl status nginx
    rm /lib/systemd/system/nginx.service
  ```
- to blacklist the evbug kernel module on controlplane host.
  ```
      vim /etc/modprobe.d/blacklist.conf file 
      blacklist evbug
  ```
- command to remove nginx package from ubuntu system
  ```
  apt remove nginx
  ```
- command to know ehich service is running on which port
  ```
    netstat -plnt|grep 9090
  ```
- command to stop apache2 service
  ```
    systemctl stop apache2
  ```
- command to update system packages
  ```
    apt-get update
  ```
- command to install wget package
  ```
    apt install wget -y
  ```
## UFW Firewall
- command to know status of ufw tool on the nodes?
  ```
    ufw status
  ```
- commands to display the rules along with rule numbers next to each rule
  ```
    ufw status numbered
  ```
- command to allow a tcp port range between 1000 and 2000 in ufw?
  ```
    ufw allow 1000:2000/tcp
  ```
- command to reset ufw rules to their default settings?
  ```
    ufw reset
  ```
- command to to allow incoming SSH connections
  ```
    ufw allow 22/tcp
  ```
- command to allow incoming connection on these ports from IP range 135.22.65.0/24 to any interface.
  ```
    ufw allow from 135.22.65.0/24 to any port 22 proto tcp
  ```
- command to enable ufw firewall
  ```
    ufw enable
  ```
- command to disable all incoming connection on port 80
  ```
  ufw deny to any port 80 proto tcp
  ```
- command to disable firewall
  ```
    ufw disable
  ```
## Seccomp
- commands/tools can be used to trace syscalls
  ```
   strace
 ```
- command to get all syscall made by command ls /root
  ```
    strace ls /root
  ```
- This profile has the default action of SCMP_ACT_ERRNO that blocks all syscalls by default. The syscalls to be allowed are part of the whitelist. This is an example of a whitelist type profile.
- default location of seccomp profile /var/lib/kubelet/seccomp
- Create a new pod called audit-nginx using the nginx image and make use of the audit.json seccomp profile in the pod's security context.
  The audit.json file is already present in the default seccomp profile path in the controlplane node.

  ```yaml
      apiVersion: v1
      kind: Pod
      metadata:
        labels:
          run: nginx
        name: audit-nginx
      spec:
        securityContext:
          seccompProfile:
            type: Localhost
            localhostProfile: profiles/audit.json
        containers:
        - image: nginx
          name: nginx
  ```

## AppArmour

- to know current status of apparmour state. commad is aa-status. Since here aa-status shows taht all profiles are loaded and in enforced, indicating apparmour is full active and stable machinge the GA(
  generally Available) status/
- default location of apparmour profiles are /etc/apparmour.d/
- to enforce a profile
  ```
    apparmor_parser -q /etc/apparmor.d/usr.sbin.nginx
  ```



  
