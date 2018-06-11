#!/usr/bin/env python3
# coding=utf-8

import pyudev
import os
from threading import Thread, Lock
from inotify import adapters
from assemblyline_client import Client
import my_logger
from socketIO_client import SocketIO
import time

# ---------- Customizable paths
# URL of Assemblyline instance
al_instance = 'https://134.190.171.253/'
# Directory where we will mount our block device
mount_dir = '/home/user/al_ui/temp_device'
# Directory where all imported files (copied from block device) are temporarily stored before being sent to AL
ingest_dir = '/home/user/al_ui/imported_files'

# ---------- Block device importing
# -- Context object used to configure pyudev to detect the devices on this computer
context = pyudev.Context()
# List of all active devices (devices that are currently plugged in)
active_devices = []
# Number of partitions who have been recognized but who have not yet had their files imported
partition_toread = 0
# True if user wants to neuter files when importing. False by default
neuter = False
# Lock object for allowing only one partition to mount at a time
mount_lock = Lock()

# ---------- Assemblyline Server communication
# List of files that have been imported from our drive, and are ready to be submitted to AL
list_to_submit = []
# List holds all potentially malicious files as determined by AL output
mal_files = []
# Number of files that have been submitted and are awaiting a response from AL
num_waiting = 0
# Whether or not our application has finished scanning all imported files
finished = True

# ---------- Kiosk communication
# Creates socket between web app and this module
socketIO = SocketIO('http://10.0.2.2:5000', verify=False)
# True when files are currently being uploaded
loading = False


def kiosk(msg):
    print msg
    socketIO.emit('to_kiosk', msg)


def block_event(action, device):
    """
    Called whenever our observer detects that a block device has been added or removed
    :param action: Was the device added or removed?
    :param device: What device?
    :return:
    """

    global partition_toread
    global finished
    global active_devices
    global socketIO

    # Called when a device is added
    if action == 'add':

        # If device is block device
        if device.subsystem == 'block':
            device_id = device.device_node

            # Announces a new device has been detected
            if device.get('DEVTYPE') == 'disk':
                socketIO.emit('device_event', 'connected')
                kiosk('clear')
                time.sleep(0.1)
                kiosk('\n--- New block device detected: ' + device_id)

                # Makes new folder to hold partitions from this disk
                path_new = os.path.normpath(ingest_dir + device_id)
                path_split = path_new.split(os.sep)
                dir_new = ''
                for x in path_split[:-1]:
                    dir_new += x + '/'
                os.system('mkdir -p ' + dir_new)

            # Creates image of USB firmware and a new Thread to import the contents of this partition
            if device.get('DEVTYPE') == 'partition':
                partition_toread += 1
                active_devices.append(device_id)
                Thread(target=copy_files, args=(device_id,), name=device_id).start()

    # Called when the active device is removed. Clears the imported cart files
    elif action == 'remove':
        if device.get('DEVTYPE') == 'partition':
            kiosk('Partition removed')
            kiosk('\nRemoving temp files')
            clear_files(device.device_node)


def copy_files(device_id):
    """
    Corresponds to new thread created by each new partition from an attached device. One by one devices are mounted,
    their contents converted to CART and sent to a corresponding imported_files folder, and then unmounted
    :param device_id: The path of the current device partition
    :return:
    """

    global neuter
    global mount_lock
    global partition_toread
    global active_devices
    global mount_dir
    global ingest_dir

    while True and len(active_devices) != 0:

        # Waits until mount_lock is available (ie. other partitions have finished mounting)
        with mount_lock:

            # Makes sure device hasn't been unplugged while waiting
            if device_id in active_devices:

                # Mounts device
                os.system('sudo /home/user/al_ui/bash_scripts/mount_block.sh ' + device_id +
                          ' ' + mount_dir)

                # Takes image of device firmware. This is commented out as there are currently no services in
                # assemblyline that read img files:
                # os.system('sudo /home/user/al_ui/bash_scripts/image_device_firmware.sh ' + device_id +
                # ' /home/user/al_ui/temp_device/usb_firm.img')

                kiosk('\n--- Partition successfully loaded: ' + device_id)

                # Makes new directory for this partition
                os.system('mkdir -p ' + ingest_dir + device_id)

                # Checks if the user wants to neuter files or not
                if neuter:
                    # Sends files to be converted to CART format
                    neuter_files(mount_dir, device_id)
                else:
                    os.system('cp -a ' + mount_dir + ' ' + ingest_dir + device_id)

                # Removes Image
                os.system('sudo /home/user/al_ui/bash_scripts/remove_dev_img.sh')

                # Unmounts device
                os.system('sudo /home/user/al_ui/bash_scripts/unmount_block.sh ' + mount_dir)

            # This partition is now finished; subtracts 1 from the partitions that need to be read and returns
            partition_toread -= 1
            return


def neuter_files(raw_dir, device_id):
    """
    Called when a block device has been successfully loaded and mounted. Scans through all files on the device and
    creates a copy in CART format within the imported_files folder, where they will be imported by Assemblyline
    :param raw_dir: Directory where usb is mounted
    :param device_id: The reference for this usb partition
    :return:
    """

    # Walks through files in given directory one by one, converting to CART and sending to imported_files
    kiosk('Uploading files...')
    for root, dirs, files in os.walk(raw_dir):
        for raw_file in files:
            output_file = ingest_dir + device_id + '/' + raw_file + '.cart'
            os.system('cart ' + '\'' + root + '/' + raw_file + '\'' + ' --outfile \'' + output_file + '\'')


def clear_files(device_id):
    """
    Called when files have successfully been uploaded to Assemblyline, or when a device is removed from the terminal
    :return:
    """

    global active_devices
    global list_to_submit
    global mal_files
    global finished
    global partition_toread

    if len(active_devices) != 0:
        active_devices.remove(device_id)

    # Removes the folder in imported_files containing the files corresponding to the removed device
    os.system('rm -rf ' + ingest_dir + device_id)
    kiosk('Temp files successfully removed: ' + device_id)

    # If all devices have been removed, resets list and clears the imported files directory
    if len(active_devices) == 0:
        list_to_submit = []
        mal_files = []
        os.system('rm -rf ' + ingest_dir + '/*')
        finished = True
        kiosk('Temporary malicious files have been cleared')
        kiosk('\n--- All devices successfully removed')
        socketIO.emit('device_event', 'disconnected')
        time.sleep(0.1)
        kiosk('\r\n')
        # time.sleep(5)
        # kiosk('clear')


def submit_thread(queue):
    """
    Watches for files that are added to the imported_files/dev folder; when new files are added, uploads and deletes
    from the folder once finished
    :param queue:
    :return:
    """

    global list_to_submit
    global num_waiting
    global loading

    # Continuously monitors the list_to_submit. If a new entry is detected, uploads to server and deletes once done
    while True:

        # Checks to make sure there are still files to be ingested
        if len(list_to_submit):

            if not loading:
                socketIO.emit('device_event', 'loading')
                loading = True

            # Pops a file path from the list of files to be submitted
            ingest_path = list_to_submit.pop()

            # Checks to make sure the file at this path still exists
            if os.path.exists(ingest_path):

                # Checks if the file is empty; ingest is unable to examine empty files. Returns a warning if one is
                # submitted
                if os.stat(ingest_path).st_size != 0:

                    # Increments up the number of files we have uploaded who have yet to receive a result from the
                    # server
                    num_waiting += 1

                    # Ingests file. Removes file from terminal once ingested
                    kiosk('Ingesting: ' + os.path.basename(ingest_path))
                    terminal.ingest(ingest_path,
                                    metadata={'path': ingest_path, 'filename': os.path.basename(ingest_path)},
                                    nq=queue, ingest_type='TERMINAL')
                    os.system('rm -f \'' + ingest_path + '\'')

                else:
                    kiosk('Unable to ingest, empty file: ' + os.path.basename(ingest_path))


def receive_thread(queue):
    """
    Monitors the server for new messages that occur when files have been successfully uploaded. Scans the results to
    see if score is high.
    :param queue:
    :return:
    """

    global mal_files
    global finished
    global partition_toread
    global list_to_submit
    global num_waiting
    global loading

    while True:

        # Takes all messages from the Assemblyline server and stores in list
        msgs = terminal.ingest.get_message_list(queue)

        # Checks if all partitions have been mounted, all files from partitions have been ingested, and all our ingested
        # files have returned messages from the server. If all these are true then we are finished ingesting files and
        # our submit and receive threads are shut down.
        # print partition_toread, len(list_to_submit), num_waiting, finished, len(mal_files), len(list_to_submit)
        if partition_toread == 0 and len(list_to_submit) == 0 and num_waiting == 0 and not finished:
            kiosk('\n--- All files have been successfully ingested')
            finished = True
            if loading:
                socketIO.emit('device_event', 'done_loading')
                loading = False
            time.sleep(0.1)
            kiosk('\r\n')
            continue

        # For each new message that comes from our Assemblyline server, outputs some info about that file. Any files
        # with a score over 500 have their sid added to the mal_files list. We subtract 1 from num_waiting each time
        # a result is output
        for msg in msgs:
            new_file = os.path.basename(msg['metadata']['path'])
            score = msg['metadata']['al_score']
            sid = msg['alert']['sid']
            kiosk('   Server Received: ' + new_file + "    " + 'sid: %s    score: %d' % (sid, score),)

            if score >= 500:
                kiosk('     [ ! ] WARNING - Potentially malicious file: ' + new_file)
                mal_files.append(sid)

            else:
                print

            # Decrements the number of submitted files who are awaiting a response from the server
            num_waiting -= 1


if __name__ == '__main__':

    my_log = my_logger.logger

    os.system('mkdir -p ' + mount_dir)
    os.system('mkdir -p ' + ingest_dir)

    # Sets up monitor and observer thread to run in background to detect addition or removal of devices
    monitor = pyudev.Monitor.from_netlink(context)
    observer = pyudev.MonitorObserver(monitor, block_event)
    observer.start()

    # Sets up Assemblyline client
    # terminal = Client(al_instance, apikey=('admin', 'S7iqqLC48e^Dk@VQ6kvnyPOFl7shuvsilx8V^QpOuy&s7KYv'), verify=False)
    terminal = Client(al_instance, auth=('admin', 'changeme'), verify=False)

    # Sets up server communication threads
    queue_name = 'ingest_queue'
    st = Thread(target=submit_thread, args=(queue_name,), name="submit_thread")
    st.daemon = True
    rt = Thread(target=receive_thread, args=(queue_name,), name="receive_thread")
    rt.daemon = True

    st.start()
    rt.start()

    # Sets up inotify to watch imported_files directory
    i = adapters.InotifyTree(ingest_dir)

    # Infinite loop watches for new additions to imported_files directory
    for event in i.event_gen():
        if event is not None:

            # Stores the event type, pathname, and filename for this event
            (_, type_names, path, filename) = event
            for e_type in type_names:

                # If our event is that we've finished writing a file to imported_files, passes that file's path into
                # our list_to_submit
                if e_type == 'IN_CLOSE_WRITE' and filename != '':
                    dir_to_ingest = path + '/' + filename
                    list_to_submit.append(dir_to_ingest)
                    finished = False
