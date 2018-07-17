#!/usr/bin/env python3
# coding=utf-8

import pyudev
import os
from threading import Thread, Lock
import threading
from assemblyline_client import Client
from inotify import adapters
# import my_logger
from socketIO_client import SocketIO
import time


# ============== Default Property Values ==============

# ---------- Customizable paths
# URL of Assemblyline instance
al_instance = 'https://134.190.171.253/'
# Directory where we will mount our block device
mount_dir = '/home/user/al_ui/temp_device'
# Directory where all imported files (copied from block device) are temporarily stored before being sent to AL
ingest_dir = '/home/user/al_ui/imported_files'
# The name given to this terminal
terminal_id = 'DEV_TERMINAL'

# ---------- Block device importing
# Context object used to configure pyudev to detect the devices on this computer
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
terminal = Client
# List of files that have been imported from our drive, and are ready to be submitted to AL
list_to_submit = []
# List of files that have been submitted to AL, on whom we are awaiting a response
list_to_receive = []
# List holds all potentially malicious files as determined by AL output
pass_files = []
# List holds all potentially malicious files as determined by AL output
mal_files = []

scrape_stage = 0

# ---------- Kiosk communication
# Creates socket between web app and this module
socketIO = SocketIO


# ============== Helper Functions ==============

def kiosk(msg):
    """
    Handles console output. Sends message to webapp and also logs
    :param msg: message to be sent
    :return:
    """

    global socketIO

    print msg

    socketIO.emit('to_kiosk', msg)


def initialize():
    """
    Constantly running loop which watches our ingest directory for changes. Any files that are copied into this
    directory are submitted to AL server
    :return:
    """

    global terminal

    print "init_workers"

    refresh_socket()
    refresh_session()

    # Connects to our Assemblyline deployment
    terminal = Client(al_instance, apikey=('admin', 'CbHIT^4L*SqLUOoNwLE5g67TaRL9IZEnmE*omXHIC8AI(G3q'), verify=False)

    # 1. Initializes pyudev observer thread that is going to monitor for device events (devices added / removed)
    monitor = pyudev.Monitor.from_netlink(context)
    observer = pyudev.MonitorObserver(monitor, block_event)
    observer.start()

    # 2. Initializes submit thread. Takes files added to list_to_submit array and submits them to AL server
    st = Thread(target=submit_thread, args=('ingest_queue',), name="submit_thread")
    st.daemon = True
    st.start()

    # 3. Initializes receive thread. This thread listens for callbacks from the AL server
    rt = Thread(target=receive_thread, args=('ingest_queue',), name="receive_thread")
    rt.daemon = True
    rt.start()

    # 4. Begins infinite loop that watches for files being added to the ingest_dir folder. Files are copied over when
    #    detected by the observer; this loop detects the new file, and adds its path to the list_to_submit array to be
    #    picked up by the submit thread
    dt = Thread(target=detect_thread, name="detect_thread")
    dt.start()


def refresh_socket():
    """
    Refreshes our socketio connection
    :return:
    """

    global socketIO

    print "refresh_socket"

    try:
        socketIO = SocketIO('http://10.0.2.2:5000', verify=False)
    except:
        time.sleep(2)
        refresh_socket()

    print "refresh_socket done"


def refresh_session():
    global list_to_submit
    global list_to_receive
    global mal_files
    global pass_files

    print "refresh_session"

    # Resets all default values
    list_to_submit = []
    list_to_receive = []
    mal_files = []
    pass_files = []


def app_response(f_name, l_name, default_settings):
    """
    Called continuously checking whether valid credentials have been entered when script first starts running. Once
    credentials have been entered, begin_scrape is set to true, and the device observer, submit, and receive threads
    are allowed to run (ie. the service starts as normal)
    :param f_name: Client first name
    :param l_name: Client last name
    :param default_settings: User settings passed down by application
    :return:
    """

    global scrape_stage

    if f_name != '' and l_name != '':
        scrape_stage = 1
        print "  User First Name: " + f_name
        print "  User Last Name: " + l_name


def session_wait():

    global scrape_stage
    print "session_wait"

    scrape_stage = 0

    while scrape_stage == 0:
        socketIO.emit("connect_request", app_response)
        socketIO.wait_for_callbacks(seconds=1)
        time.sleep(1)


def check_done():
    """
    Checks whether or not all files have been imported from our device
    :return:
    """
    global socketIO
    global scrape_stage

    # Checks if all partitions have been mounted, all files from partitions have been ingested, and all our ingested
    # files have returned messages from the server. If all these are true then we are finished ingesting files and
    # our submit and receive threads are shut down. Once lists have been emitted they are reset.
    # print
    # print "partition_toread: " + str(partition_toread)
    # print "list_to_submit: " + str(len(list_to_submit))
    # print "list_to_receive: " + str(len(list_to_receive))
    # print
    if partition_toread == 0 and len(list_to_submit) == 0 and len(list_to_receive) == 0 and scrape_stage == 2:
        scrape_stage = 3
        print "Threads: " + str(threading.activeCount())
        kiosk('\n--- All files have been successfully ingested')
        socketIO.emit('device_event', 'done_loading')
        time.sleep(0.1)
        kiosk("\r\n")
        time.sleep(0.1)
        socketIO.emit('pass_files', pass_files)
        time.sleep(0.1)
        socketIO.emit('mal_files', mal_files, terminal_id)
        time.sleep(0.1)


# ============== Backend Functions ==============

def block_event(action, device):
    """
    Called whenever our observer detects that a block device has been added or removed.
    :param action: Was the device added or removed?
    :param device: What device?
    :return:
    """

    global pass_files
    global mal_files
    global partition_toread
    global active_devices
    global socketIO

    # Called when a device is added
    if action == 'add':

        # If device is block device
        if device.subsystem == 'block':
            device_id = device.device_node
            print device_id

            # Announces a new device has been detected
            if device.get('DEVTYPE') == 'disk':
                socketIO.emit('device_event', 'connected')

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

    while len(active_devices) != 0:

        # Waits until mount_lock is available (ie. other partitions have finished mounting)
        with mount_lock:

            # Makes sure device hasn't been unplugged while waiting
            if device_id in active_devices:

                # Mounts device
                os.system('sudo /home/user/al_ui/bash_scripts/mount_block.sh ' + device_id +
                          ' ' + mount_dir)

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
    global partition_toread
    global socketIO

    if len(active_devices) != 0:
        active_devices.remove(device_id)

    # Removes the folder in imported_files containing the files corresponding to the removed device
    os.system('rm -rf ' + ingest_dir + device_id)

    # If all devices have been removed, resets list and clears the imported files directory
    if len(active_devices) == 0:
        os.system('rm -rf ' + ingest_dir + '/*')
        refresh_session()
        session_wait()
        socketIO.emit('device_event', 'disconnected')
        print "Device Removed"


# ============== AL Server Interaction Threads ==============

def detect_thread():
    i = adapters.InotifyTree(ingest_dir)
    # Loop watches for new additions to imported_files directory
    for event in i.event_gen():
        if event is not None:
            # Stores the event type, pathname, and filename for this event
            (_, type_names, path, filename) = event
            for e_type in type_names:
                # If our event is that we've finished writing a file to imported_files, passes that file's path into
                # our list_to_submit
                if e_type == 'IN_CLOSE_WRITE' and filename != '':
                    dir_to_ingest = path + '/' + filename
                    socketIO.emit("ingest_status", "submit_file")
                    list_to_submit.append(dir_to_ingest)
                    print "        Push: " + dir_to_ingest


def submit_thread(queue):
    """
    Watches for files that are added to the imported_files/dev folder; when new files are added, uploads and deletes
    from the folder once finished
    :param queue:
    :return:
    """

    global list_to_submit
    global terminal
    global socketIO
    global list_to_receive
    global terminal_id
    global scrape_stage

    # Continuously monitors the list_to_submit. If a new entry is detected, uploads to server and deletes once done
    while True:

        if len(list_to_submit) and scrape_stage > 0:

            if scrape_stage != 2:
                socketIO.emit('device_event', 'loading')
                scrape_stage = 2
                time.sleep(2)

            # Pops a file path from the list of files to be submitted
            ingest_path = list_to_submit.pop()
            print "        Pop: " + ingest_path

            # Checks to make sure the file at this path still exists
            if os.path.exists(ingest_path):

                # Checks if the file is empty; ingest is unable to examine empty files. Returns a warning if one is
                # submitted
                if os.stat(ingest_path).st_size != 0:

                    # Ingests file. Removes file from terminal once ingested
                    kiosk('Ingesting: ' + os.path.basename(ingest_path))
                    list_to_receive.append(os.path.basename(ingest_path))

                    terminal.ingest(ingest_path,
                                    metadata={'path': ingest_path, 'filename': os.path.basename(ingest_path)},
                                    nq=queue, ingest_type=terminal_id)
                    os.system('rm -f \'' + ingest_path + '\'')

                else:
                    kiosk('Unable to ingest, empty file: ' + os.path.basename(ingest_path))

        else:
            time.sleep(1)


def receive_thread(queue):

    """
    Monitors the server for new messages that occur when files have been successfully uploaded. Scans the results to
    see if score is high.
    :param queue:
    :return:
    """

    global pass_files
    global mal_files
    global partition_toread
    global list_to_submit
    global active_devices
    global terminal
    global socketIO

    while True:

        if len(list_to_receive):
            # Takes all messages from the Assemblyline server and stores in list
            msgs = terminal.ingest.get_message_list(queue)

            # For each new message that comes from our Assemblyline server, outputs some info about that file. Any files
            # with a score over 500 have their sid added to the mal_files list. We subtract 1 from num_waiting each time
            # a result is output
            for msg in msgs:
                new_file = os.path.basename(msg['metadata']['path'])
                if new_file in list_to_receive:
                    list_to_receive.remove(new_file)
                    socketIO.emit("ingest_status", "receive_file")

                    score = msg['metadata']['al_score']
                    sid = msg['alert']['sid']
                    kiosk('   Server Received: ' + new_file)

                    if score >= 500:
                        kiosk('        [ ! ] WARNING - Potentially malicious file: ' + new_file)
                        full_msg = terminal.submission.full(sid)
                        full_path = full_msg['submission']['metadata']['path']
                        full_msg['submission']['metadata']['path'] = full_path[full_path.find('temp_device') + 11:]
                        mal_files.append(full_msg)

                    elif score > 0:
                        full_path = msg['metadata']['path']
                        msg['metadata']['path'] = full_path[full_path.find('temp_device') + 11:]
                        pass_files.append(msg)
                        print

        else:
            check_done()
            time.sleep(1)


# ============== Initialization ==============

if __name__ == '__main__':

    os.system('mkdir -p ' + mount_dir)
    os.system('mkdir -p ' + ingest_dir)

    initialize()
    session_wait()
