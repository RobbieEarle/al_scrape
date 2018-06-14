# al_scrape
This script runs perpetually as a background service on a self contained virtual machine, communicating as necessary
with a remote Assemblyline server. Progress and results are output to the al_da web app running on the host machine.

Our Assemblyline instance is to be deployed on a separate machine within the same network - al_scrape sends files to
this server directly.

Our al_da web app is to be deployed on the host machine which is housing the VM on which al_scrape is running. This is
to protect against potentially malicious files: after a new device is scanned, the VM on which al_scrape is running is
wiped / returned to a previous snapshot. The files themselves are neutered and sent to the Assemblyline server, and the
web app simply provides a UI for the user to receive scan progress updates and to view the messages that come back from
the server.
