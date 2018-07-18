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
import traceback


# ============== Default Property Values ==============

# ---------- Initialization Variables
# The name given to this terminal
terminal_id = ''
# Directory where we will mount our block device
mount_dir = '/home/user/al_ui/temp_device'
# Directory where all imported files (copied from block device) are temporarily stored before being sent to AL
ingest_dir = '/home/user/al_ui/imported_files'

# ---------- Block device importing
# List of all active devices (devices that are currently plugged in)
active_devices = []
# Number of partitions who have been recognized but who have not yet had their files imported
partition_toread = 0
# True if user wants to neuter files when importing. False by default
neuter = False
# Lock object for allowing only one partition to mount at a time
mount_lock = Lock()

# ---------- Assemblyline Server communication
terminal = None
# List of files that have been imported from our drive, and are ready to be submitted to AL
list_to_submit = []
# List of files that have been submitted to AL, on whom we are awaiting a response
list_to_receive = []
# List holds all potentially malicious files as determined by AL output
pass_files = []
# List holds all potentially malicious files as determined by AL output
mal_files = []
# Identifies where our user is in the scrape process
scrape_stage = 0

# ---------- Kiosk communication
# Creates socket between web app and this module
socketIO = None


# ============== Helper Functions ==============

def kiosk(msg):
    """
    Handles console output. Sends message to webapp and also logs
    :param msg: message to be sent
    :return:
    """
    global socketIO

    print msg
    socketIO.emit('be_to_kiosk', msg)


def new_session(settings):
    global terminal, terminal_id, scrape_stage

    print settings

    try:
        terminal = Client(settings["address"], apikey=(settings["username"], settings["api_key"]), verify=False)
        terminal_id = settings["id"]
    except Exception as e:
        print traceback.format_exception_only(type(e), e)[0]

    if terminal is not None:

        scrape_stage = 0

        # 2. Initializes submit thread. Takes files added to list_to_submit array and submits them to AL server
        st = Thread(target=submit_thread, args=('ingest_queue',), name="submit_thread")
        st.start()

        # 3. Initializes receive thread. This thread listens for callbacks from the AL server
        rt = Thread(target=receive_thread, args=('ingest_queue',), name="receive_thread")
        rt.start()

    else:
        print "Terminal Error - Output to Kiosk"


def initialize():
    """
    Constantly running loop which watches our ingest directory for changes. Any files that are copied into this
    directory are submitted to AL server
    :return:
    """
    global terminal

    print "initialize"

    # Refreshes application's websocket connection to front end application
    refresh_socket()

    # if terminal is not None:

    # 1. Initializes pyudev observer thread that is going to monitor for device events (devices added / removed)
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    observer = pyudev.MonitorObserver(monitor, block_event)
    observer.start()

    # 4. Begins infinite loop that watches for files being added to the ingest_dir folder. Files are copied over when
    #    detected by the observer; this loop detects the new file, and adds its path to the list_to_submit array to be
    #    picked up by the submit thread
    # dt = Thread(target=detect_thread, name="detect_thread")
    # dt.start()

    socketIO.emit("be_retrieve_settings", new_session)
    socketIO.wait_for_callbacks(seconds=1)

    # else:
    #     print "Init Fail"


def refresh_socket():
    """
    Refreshes our socketio connection to external Flask application
    :return:
    """
    global socketIO

    print "refresh_socket"

    socketIO = SocketIO('http://10.0.2.2:5000', verify=False)

    print "refresh_socket done"


def refresh_session():
    """
    Resets to default values our arrays that were populated during the last session
    :return:
    """
    global list_to_submit
    global list_to_receive
    global mal_files
    global pass_files

    print "refresh_session"

    list_to_submit = []
    list_to_receive = []
    mal_files = []
    pass_files = []


def app_response(f_name, l_name, default_settings):
    """
    Called continuously by the session_wait() function, checking whether valid credentials have been entered when
    script first starts running. Once credentials have been entered, scrape_stage is set to 1, allowing our submit
    thread to start running
    :param f_name: client first name
    :param l_name: client last name
    :param default_settings: user settings passed down by application
    :return:
    """
    global scrape_stage

    # If user credentials have been added, moves to stage 1
    if f_name != '' and l_name != '':
        scrape_stage = 1
        print "  User First Name: " + f_name
        print "  User Last Name: " + l_name


# def new_session():
#     """
#     Runs in between sessions; waits for a user to input their credentials
#     :return:
#     """
#     global scrape_stage
#
#     print "session_wait"
#
#     scrape_stage = 0
#     while scrape_stage == 0:
#         socketIO.emit("sd_connect_request", app_response)
#         socketIO.wait_for_callbacks(seconds=1)
#         time.sleep(1)
#
#     print "session_wait done"


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
    if partition_toread == 0 and len(list_to_submit) == 0 and len(list_to_receive) == 0 and scrape_stage == 2:
        scrape_stage = 3
        print "Threads: " + str(threading.activeCount())
        socketIO.emit('be_device_event', 'done_loading')
        time.sleep(0.1)
        socketIO.emit('be_pass_files', pass_files)
        time.sleep(0.1)
        socketIO.emit('be_mal_files', mal_files, terminal_id)
        time.sleep(0.1)


# ============== MonitorObserver Functions ==============

def block_event(action, device):
    """
    Called by our observer thread whenever it detects that a block device has been added or removed.
    :param action: passes in information about the type of event that observer noticed
    :param device: passes in information about the device that triggered the event
    :return:
    """

    global partition_toread
    global active_devices
    global socketIO

    device_id = device.device_node

    # Called when a device is added
    if action == 'add' and device.subsystem == 'block':

        # The DEVTYPE "disk" occurs once when a new device is detected
        if device.get('DEVTYPE') == 'disk':

            # Announces a new device has been detected to front end
            socketIO.emit('be_device_event', 'connected')
            time.sleep(0.1)
            socketIO.emit("be_retrieve_settings", new_session)
            socketIO.wait_for_callbacks(seconds=1)

            # Makes new folder to hold partitions from this disk
            path_new = os.path.normpath(ingest_dir + device_id)
            path_split = path_new.split(os.sep)
            dir_new = ''
            for x in path_split[:-1]:
                dir_new += x + '/'
            os.system('mkdir -p ' + dir_new)

        # The DEVTYPE "partition" occurs once for each partition on a given device. If the device is not
        # partitioned, this event will still fire once for the main device drive
        elif device.get('DEVTYPE') == 'partition':

            # Increments the number of partitions that are waiting to be read
            partition_toread += 1

            # Adds this device to the array of devices that are currently connected
            active_devices.append(device_id)

            # Creates new thread to copy all files from this partition to our directory that is being watched by the
            # submit thread
            Thread(target=copy_files, args=(device_id,), name=device_id).start()

    # Called when an active device is removed. Clears the imported cart files
    elif action == 'remove':
        if device.get('DEVTYPE') == 'partition':
            clear_files(device_id)


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
                    # If not copies files directly into directory to be ingested
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
    Called when all files from a partition have successfully been uploaded to Assemblyline, or when a device is
    removed from the terminal
    :return:
    """

    global active_devices
    global socketIO

    # Removes this partition from the array of currently connected devices
    if len(active_devices) != 0:
        active_devices.remove(device_id)

    # Removes the folder in imported_files containing the files corresponding to the removed device
    os.system('rm -rf ' + ingest_dir + device_id)

    # If all devices have been removed, resets list and clears the imported files directory
    if len(active_devices) == 0:
        socketIO.emit('be_device_event', 'disconnected')
        os.system('rm -rf ' + ingest_dir + '/*')
        refresh_session()
        # new_session()
        print "Device Removed"


# ============== Continuously Running Background Threads ==============

def detect_thread():
    """
    Background thread runs perpetually, watching ingest_dir for files that are copied over from a mounted device. When
    files are detected in this directory their paths are added to an array to be submitted by our submit_thread
    :return:
    """
    global list_to_submit

    i = adapters.InotifyTree(ingest_dir)
    while True:
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
                        socketIO.emit("be_ingest_status", "submit_file")
                        list_to_submit.append(dir_to_ingest)
                        print "        Push: " + dir_to_ingest


def submit_thread(queue):
    """
    Watches for files that are added to the imported_files/dev folder; when new files are added, uploads and deletes
    from the folder once finished
    :param queue: the name of the ingest queue we want to add this file to
    :return:
    """

    global list_to_submit
    global terminal
    global socketIO
    global list_to_receive
    global terminal_id
    global scrape_stage

    # Continuously monitors the list_to_submit. If a new entry is detected, uploads to server and deletes once done
    while scrape_stage > 0 and scrape_stage < 3:

        # Begins to submit only if there are files to submit, and we are not in scrape stage 0 (ie. user credentials
        # have been entered)
        if len(list_to_submit):

            # Once file submission begins we enter scrape_stage 2
            if scrape_stage != 2:
                socketIO.emit('be_device_event', 'loading')
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

                    # Outputs the name of file to be ingested to the front end
                    kiosk('Ingesting: ' + os.path.basename(ingest_path))

                    # Appends the file to the array of files in regards to which we are waiting for a response from the
                    # Assemblyline server
                    list_to_receive.append(os.path.basename(ingest_path))

                    # Ingests the file (submits to Assemblyline server via ingest API)
                    terminal.ingest(ingest_path,
                                    metadata={'path': ingest_path, 'filename': os.path.basename(ingest_path)},
                                    nq=queue, ingest_type=terminal_id)

                    # Deletes this file
                    os.system('rm -f \'' + ingest_path + '\'')

                else:
                    kiosk('Unable to ingest, empty file: ' + os.path.basename(ingest_path))

        else:
            time.sleep(1)


def receive_thread(queue):
    """
    Monitors the server for new messages that occur when files have been successfully uploaded. Scans the results to
    see if score is high.
    :param queue: the name of the ingest queue from which we want to retrieve server messages
    :return:
    """

    global pass_files
    global mal_files
    global partition_toread
    global list_to_submit
    global active_devices
    global terminal
    global socketIO

    while scrape_stage != 3:

        # Listens for events only if we are expecting more files from this session
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
                    socketIO.emit("be_ingest_status", "receive_file")

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

    # Creates directories to be used by our application to mount devices, and to hold files that are awaiting ingestion
    os.system('mkdir -p ' + mount_dir)
    os.system('mkdir -p ' + ingest_dir)

    # Initializes application
    initialize()
