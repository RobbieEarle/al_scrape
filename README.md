# Overview

Assemblyline Scrape (al_scrape) is a script that runs in conjunction with the Assemblyline Device Audit (al_da) 
front end application. These applications are intended to be run on a single terminal (Kiosk), into which users can
attach block devices in order to have their contents scraped and submitted to a remote Assemblyline server for 
analysis.

Assemblyline Scrape is intended to run perpetually as a background service within a VirtualBox VM. The host machine on 
which this VM is running should have al_da running on it, and thus be hosting our front end web app. Assemblyline 
Scrape's purpose is as follows:

1. Listen for new devices that are attached to the Kiosk
2. When a new block device is detected, send copies of its contents to the Assemblyline server for analysis
3. Receive messages that come back from the server regarding potentially dangerous files
4. Output progress updates and scan results to Assemblyline Device Audit

# Installation

### On Host Machine

##### Installing VirtualBox

