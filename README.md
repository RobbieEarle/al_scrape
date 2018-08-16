# Overview

Assemblyline Scrape (al_scrape) is a service that runs in conjunction with the Assemblyline Device Audit (al_da) 
front end application. These applications are intended to be run together on a single terminal (Kiosk), into which
users can attach block devices in order to have their contents scraped and submitted to a remote Assemblyline server
for analysis.

Assemblyline Scrape is intended to run perpetually as a background service within a VirtualBox VM. The VM on which
al_scrape is running should be hosted on a machine running al_da (ie. a machine hosting a deployment of our front end 
application). Assemblyline Scrape's purpose is as follows:

1. Listen for new devices that are attached to the Kiosk
2. When a new block device is detected, send copies of its contents to the Assemblyline server for analysis
3. Receive messages that come back from the server regarding potentially dangerous files
4. Output progress updates and scan results to Assemblyline Device Audit front end

# Installation

### Pre-requisites

- [These instructions](https://github.com/RobbieEarle/al_da) should have been completed up until the point where it
recommends installing al_scrape

### Creating new VM

- Download Ubuntu 16.04.x Server install image ([here](http://releases.ubuntu.com/))
- In VirtualBox, select New. Create a new Ubuntu (64-bit) VM and name it 'alda_sandbox'. Allow for at least 6000 MB 
RAM, 20 GB storage

### Install Ubuntu 16.04.x OS

##### Boot from Ubuntu 16.04.x Server install image and follow the menu guidance below:

- English -> Install Ubuntu Server
- Language: English (Default)
- Country: United States (Default)
- Detected Keyboard Layout: No (Default)
- Keyboard Origin: English US (Default)
- Keyboard Layout: English US (Default)
- Select a primary network interface (using the first enumerated interface)
- Hostname: Your pre-determined hostname. Typically of the form al-linux-<N>
- User: user
- Password: xxxx
- Encrypt your home directory: No (Default)
- Timezone: Eastern

##### If it prompts you that a partition is in use, select 'Yes' for unmount partitions.

- Disk: Guided - use entire disk and set up LVM
- If prompted select disk to install on, this disk will be formatted
- Write changes to disk: \<YES>
- Choose: No automatic updates
- Ensure 'standard system utilities' and 'OpenSSH server' is checked and continue
- Install Grub boot loader: \<YES>
- Installation complete \<Continue>
- The system will reboot

### On First Login

##### Install al_scrape

- `sudo apt-get update`
- `sudo apt-get -y upgrade`
- `cd /opt`
- `sudo git clone https://github.com/RobbieEarle/al_scrape.git`
- `sudo visudo`
    - Beneath `%sudo    ALL=(ALL:ALL) ALL` enter:
        - >`user ALL=(ALL) NOPASSWD: /opt/al_scrape/bash_scripts/mount_block.sh`\
        `user ALL=(ALL) NOPASSWD: /opt/al_scrape/bash_scripts/unmount_block.sh`
    - *Note: if you set your username to something other than 'user' while setting up your OS, replace the 'user' at 
    the beginning of the above to statements with whatever your chose
    - Press ctrl-x to exit, y to save, and enter to overwrite existing visudo file
- `python /opt/al_scrape/install/install_alscrape.py`

### Create VM snapshot

- Open up VirtualBox on your host machine and click on alda_sandbox (which should be running)
- Click on Machine Tools > Snapshots
- Click on 'Take'
- Name your new snapshot alda_clean

### Done

At this point al_scrape should be running as a service at all times on this VM (you can check its status with
`sudo service al_scrape status`). We can now exit our new VM and finish installing al_da by following the instructions 
found [here](https://github.com/RobbieEarle/al_da).
