# Overview

Assemblyline Scrape (al_scrape) is a script that runs in conjunction with the Assemblyline Device Audit (al_da) 
front end application. These applications are intended to be run on a single terminal (Kiosk), into which users can
attach block devices in order to have their contents scraped and submitted to a remote Assemblyline server for 
analysis.

Assemblyline Scrape is intended to run perpetually as a background service within a VirtualBox VM. The machine on which
al_da is deployed (ie. the machine hosting our front end application) should be the host machine on which the al_scrape
VM is running. Assemblyline Scrape's purpose is as follows:

1. Listen for new devices that are attached to the Kiosk
2. When a new block device is detected, send copies of its contents to the Assemblyline server for analysis
3. Receive messages that come back from the server regarding potentially dangerous files
4. Output progress updates and scan results to Assemblyline Device Audit

# Installation

**NOTE: Currently in the process of making an installation script that will simplify the installation process. In the
meantime the following steps can be followed to get al_scrape working*

### Pre-requisites

- [These instructions](https://github.com/RobbieEarle/al_da) should have been completed up until the point where it
recommends installing al_scrape

### Creating new VM

- Download Ubuntu 16.04.x Server install image ([here](http://releases.ubuntu.com/))
- In VirtualBox, select New. Create a new Ubuntu (64-bit) VM and name it 'alda_sandbox'. Allow for at least 6000 MB 
RAM, 20 GB storage.

### Install Ubuntu 16.04.x OS

**Boot from Ubuntu 16.04.x Server install image and follow the menu guidance below:**

- English -> Install Ubuntu Server
- Language: English (Default)
- Country: United States (Default)
- Detected Keyboard Layout: No (Default)
- Keyboard Origin: English US (Default)
- Keyboard Layout: English US (Default)
- Select a primary network interface (using the first enumerated interface).
- Hostname: Your pre-determined hostname. Typically of the form al-linux-<N>.
- User: user
- Password: xxxx
- Encrypt your home directory: No (Default)
- Timezone: Eastern

**If it prompts you that a partition is in use, select 'Yes' for unmount partitions.**

- Disk: Guided - use entire disk and set up LVM.
- If prompted select disk to install on, this disk will be formatted.
- Write changes to disk: \<YES>
- Choose: No automatic updates
- Ensure 'standard system utilities' and 'OpenSSH server' is checked and continue.
- Install Grub boot loader: \<YES>
- Installation complete \<Continue>
- The system will reboot.

### On First Login

**Install Dependencies**

- `sudo apt-get update`
- `sudo apt-get upgrade`
- `sudo apt install git`
- `sudo apt install python2.7 python-pip`
- `sudo pip install assemblyline-client==3.7.3`
- `sudo pip install cryptography==2.3`
- `sudo pip install flask==1.0.2`
- `sudo pip install inotify==0.2.9`
- `sudo pip install pyudev==0.21.0`
- `sudo pip install socketio==0.1.3`
- `sudo pip install socketio-client==0.7.2`

**Install al_scrape**

- `cd /home/user`
- `sudo git clone https://github.com/RobbieEarle/al_scrape.git`
- `cd /home/user/al_scrape/bash_scripts`
- `sudo visudo`
    - Beneath `%sudo    ALL=(ALL:ALL) ALL` enter:
        - >`user ALL=(ALL) NOPASSWD: /home/user/al_scrape/bash_scripts/mount_block.sh`\
        `user ALL=(ALL) NOPASSWD: /home/user/al_scrape/bash_scripts/unmount_block.sh`\
        `user ALL=(ALL) NOPASSWD: /home/user/al_scrape/bash_scripts/image_device_firmware.sh`\
        `user ALL=(ALL) NOPASSWD: /home/user/al_scrape/bash_scripts/remove_dev_img.sh`
    - Press ctrl-x to exit, y to save, and enter to overwrite existing visudo file
- `sudo chmod 700 mount_block.sh`
- `sudo chmod 700 unmount_block.sh`
- `sudo chmod 700 image_device_firmware.sh`
- `sudo chmod 700 remove_dev_img.sh`

**Make al_scrape run as a service**
    
- `sudo vi /lib/systemd/system/al_scrape.service`
- Add the following content to this file:
    - > [Unit]\
Description=Copies files from device and uploads to Assemblyline server
After=multi-user.target\
[Service]\
Type=simple\
ExecStart=/usr/bin/python3 /home/user/al_scrape/scrape_drive.py\
StandardInput=tty-force\
User=user\
Restart=always\
&nbsp; RestartSec=10\
[Install]\
WantedBy=multi-user.target
- `sudo systemctl daemon-reload`
- `sudo systemctl enable al_scrape.service`
- `sudo systemctl start al_scrape.service`

**Create VM snapshot**

- `sudo service al_scrape restart`
- Open up VirtualBox on your host machine and click on alda_sandbox (which should be running)
- Click on Machine Tools > Snapshots
- Click on 'Take'
- Name your new snapshot alda_clean

**Done**

At this point al_scrape should be running as a service at all times on this VM (you can check its status with
`sudo service al_scrape status`). We can now exit our new VM and finish installing al_da by following the instructions 
found [here](https://github.com/RobbieEarle/al_da).
