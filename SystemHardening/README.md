# cks-prep

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
- 
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

  
