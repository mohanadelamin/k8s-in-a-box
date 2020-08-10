# k8s-in-a-box

This script  will install a linux CentOS VM with kubernetes installed.
The kubernetes environment is a single node. Master node is untaint to allow pod deployment.

This script work VMware Fusion or VMware workstation.

The VM should be deployed and ready in less than 5 minutes :)

## Prerequisites

1.  VMware Fusion or VMware Workstation.
2.  Python 3. you can check you machine if you have python 3 by running the following command from terminal (MAC) or PowerShell (Windows)
```
python --version
or
python3 --version
```
3- The VM will have static IP 192.168.55.144 and it will be attached to vmnet8.

So VMware fusion or VMware workstation vmnet8 network need to be configured with subnet 192.168.55.0/24. If you already have Lab in the box installed then you are good to go. other wise please change the subnet. so the inastation can finish successfully.
You can change the network after the installation.

Use python3 if your default python is 2.x

## Usage

### Step 1. Download the image ova
Image hash:
```
md5    = bfb77c5e74cbb03a1dc738052ada0b89
SHA1   = 05d13b2f7cb6d2120fedee85013bc7f23efbbf69
SHA256 = 27a9e9aa3374dd3bb1f9adc6f8f1209920c4ecbcb9c4d62ae88e85d4f330845c
```
### Step 2. Download the script files. The script files need to be downloaded on the same directory as the ova. This is to prevent the script from requesting permission to find the ova in other directories. 

MacOS: (--no-check-certificate is needed if you are running behind a firewall with decryption enabled.)
```
wget --no-check-certificate https://raw.githubusercontent.com/mohanadelamin/k8s-in-a-box/master/requirements.txt
wget --no-check-certificate https://raw.githubusercontent.com/mohanadelamin/k8s-in-a-box/master/k8s-install.py
```

Windows: (Run the following commands from PowerShell. The Certificate validation command is needed only if you are running behind a firewall with decryption enabled.)
```
$client = new-object System.Net.WebClient
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$client.DownloadFile("https://raw.githubusercontent.com/mohanadelamin/k8s-in-a-box/master/requirements.txt",".\requirements.txt")
$client.DownloadFile("https://raw.githubusercontent.com/mohanadelamin/k8s-in-a-box/master/k8s-install.py",".\k8s-install.py")
```

### Step 3. Install the required  python modules (requests & paramiko)
```
pip3 install -r requirements.txt 
```

### Step 4. Run the script (use python3 instead of python if you default is python 2.7)
```
python k8s-install.py
```


## Example:
```
#python3 k8s-install.py
2020-08-10 21:07:25,550 INFO: Searching for the ova file k8s-lab.ova
2020-08-10 21:07:25,550 INFO: OVA file found at ./k8s-lab.ova
2020-08-10 21:07:25,569 INFO: I am working on a MacOS
2020-08-10 21:07:25,569 INFO: unpacking k8s-lab.ova to /Users/melamin/Virtual Machines.localized
Opening OVA source: ./k8s-lab.ova
The manifest validates
Opening VMX target: /Users/melamin/Virtual Machines.localized
Writing VMX file: /Users/melamin/Virtual Machines.localized/k8s-lab.vmwarevm/k8s-lab.vmx
Transfer Completed
Completed successfully
2020-08-10 21:08:02,996 INFO: OVA Unpacking completed!
2020-08-10 21:08:02,997 INFO: starting the VM
2020-08-10 21:08:04,708 INFO: k8s VM is deployed. waiting for the for ssh to be ready
2020-08-10 21:08:04,769 INFO: Trying to open a SSH connection to 192.168.55.144
2020-08-10 21:08:24,427 INFO: Connected (version 2.0, client OpenSSH_7.4)
2020-08-10 21:08:24,499 INFO: Authentication (publickey) failed.
2020-08-10 21:08:24,522 INFO: Authentication (password) successful!
2020-08-10 21:08:24,523 INFO: SSH connection to 192.168.55.144 opened successfully
2020-08-10 21:08:24,523 INFO: Waiting for kubelet to be ready. It may take up to 5 min.
2020-08-10 21:08:24,734 ERROR: The connection to the server 192.168.55.144:6443 was refused - did you specify the right host or port?

2020-08-10 21:08:24,735 INFO: Checking cluster status. Retry #1 out of 10
2020-08-10 21:09:24,830 ERROR: The connection to the server 192.168.55.144:6443 was refused - did you specify the right host or port?

2020-08-10 21:09:24,830 INFO: Checking cluster status. Retry #2 out of 10
2020-08-10 21:10:24,933 ERROR: The connection to the server 192.168.55.144:6443 was refused - did you specify the right host or port?

2020-08-10 21:10:24,934 INFO: Checking cluster status. Retry #3 out of 10
NAME                STATUS   ROLES    AGE    VERSION
k8s-lab.lab.local   Ready    master   2d6h   v1.17.8

2020-08-10 21:11:25,136 INFO: You can now ssh to root@192.168.55.144 using password PaloAlto!123
```