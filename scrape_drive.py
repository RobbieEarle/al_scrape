#!/usr/bin/env python3
# coding=utf-8


import pyudev
import os
import sys
from threading import Thread, Lock
from assemblyline_client import Client
from inotify import adapters
import inotify
from socketIO_client import SocketIO
import time

import logging


# ============== Logging ==============

class OutputHandler(logging.Handler):

    def __init__(self, socket, *args, **kwargs):
        logging.Handler.__init__(self, *args, **kwargs)
        self.socketio = socket

    def emit(self, record):
        self.socketio.emit('logging', self.format(record))


class StreamToLogger(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, log_level):
        self.logger = logger
        self.log_level = log_level
        self.linebuf = '\r\n'

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.linebuf = self.linebuf + line + "\r\n"
        self.logger.log(self.log_level, self.linebuf)


# format_str = '%(asctime)s: %(levelname)s:\t %(name)s: %(message)s'
# date_format = '%Y-%m-%d %H:%M:%S'
formatter = logging.Formatter('%(levelname)s: %(name)s: %(message)s')
my_logger = logging.getLogger("alda_sandbox")
my_logger.setLevel(logging.DEBUG)

sys.stderr = StreamToLogger(my_logger, logging.ERROR)

# ============== Default Property Values ==============

# ---------- Initialization Variables
# The name given to this terminal
terminal_id = ''

# ---------- Block device importing
# List of all active devices (devices that are currently plugged in)
active_devices = []
# Number of partitions who have been recognized but who have not yet had their files imported
partition_toread = 0
# Lock object for allowing only one partition to mount at a time
mount_lock = Lock()

# ---------- Assemblyline Server communication
# To hold reference to Assemblyline client
terminal = None
# Inotify observer
dir_observer = inotify.adapters.Inotify()
# List of files that have been detected on our mounted device, and are ready to be submitted to AL
list_to_submit = []
# List of files that have been submitted to AL, on whom we are awaiting a response
list_to_receive = []
# List of directories that have an inotify watch placed on them
list_to_watch = []
# List holds all safe files as determined by AL output
pass_files = []
# List holds all potentially malicious files as determined by AL output
mal_files = []
# Identifies where our user is in the scrape process
scrape_stage = 0

# ---------- Kiosk communication
# Creates socket between web app and this module
socketIO = None


# ============== Upkeep Functions ==============

def initialize():
    """
    Called when application is executed - ensures socketio is linked to the front end; starts our observer thread to
    watch for new devices; starts infinite loop watching for new files to submit
    :return:
    """
    global list_to_submit, dir_observer, list_to_watch

    # Refreshes application's websocket connection to front end application
    refresh_socket()

    # Tell front end that application is ready to receive device

    # Initializes pyudev observer thread that is going to monitor for device events (devices added / removed)
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    device_observer = pyudev.MonitorObserver(monitor, block_event)
    device_observer.start()

    dir_observer.add_watch('/tmp/imported_files')
    while True:
        for event in dir_observer.event_gen():
            if event is not None:
                (header, type_names, watch_path, filename) = event
                for e_type in type_names:
                    # If our event is that we've finished writing a file to imported_files, passes that file's path into
                    # our list_to_submit
                    new_file = watch_path + '/' + filename
                    if e_type == 'IN_CREATE' and type_names[0] == 'IN_ISDIR' and filename != '':
                        dir_observer.add_watch(new_file)
                        list_to_watch.append(new_file)
                        my_logger.info("Created and added inotify watch to directory: " + new_file)
                    if e_type == 'IN_CLOSE_WRITE' and filename != '':
                        list_to_submit.append(new_file)


def refresh_socket():
    """
    Called on initialization. Refreshes our socketio connection to external Flask application
    :return:
    """
    global socketIO

    try:
        socketIO = SocketIO('http://10.0.2.2:5000', verify=False)

        socket_handler = OutputHandler(socket=socketIO, level=logging.DEBUG)
        socket_handler.setFormatter(formatter)
        my_logger.addHandler(socket_handler)

    except Exception:
        time.sleep(3)
        refresh_socket()


def refresh_session():
    """
    Called when a new session begins. Resets our arrays that were populated during the last session to their default
    values
    :return:
    """
    global list_to_submit
    global list_to_receive
    global mal_files
    global pass_files

    list_to_submit = []
    list_to_receive = []
    mal_files = []
    pass_files = []


# ============== Session Functions ==============

def session_login():
    """
    Called by our block event function whenever a new device is detected. Requests the Assemblyline login credentials
    from our Flask app; once received, calls new session
    :return:
    """
    socketIO.emit("be_retrieve_settings", new_session)
    socketIO.wait_for_callbacks(seconds=1)


def new_session(settings):
    """
    Called once our Assemblyline login credentials have been received. Refreshes our session variables; tries to
    connect to the Assemblyline server: if able, tells the front end and waits to receive back the start signal (this
    comes only once all mandatory credentials have been entered). When start signal is received, starts up the submit
    and receive threads
    :param settings:
    :return:
    """
    global terminal, terminal_id, scrape_stage

    my_logger.info("Beginning new session")
    time.sleep(0.1)

    # Scrape Stage 0 - Connecting to Assemblyline server
    scrape_stage = 0
    refresh_session()

    # Tries to connect to Assemblyline server; if not able to, prints error
    terminal = None
    try:
        terminal = Client(settings["address"], apikey=(settings["username"], settings["api_key"]), verify=False)
        terminal_id = settings["id"]
        terminal.ingest.get_message_list(terminal_id)
    except Exception as e:
        socketIO.emit('be_device_event', 'al_server_failure')
        my_logger.error("Error: " + str(e))
        time.sleep(0.1)

    # If server connection is successful
    if terminal is not None:

        # Outputs successful connection message to front end
        socketIO.emit('be_device_event', 'al_server_success')

        # Scrape Stage 1 - Server connected; awaiting credentials
        scrape_stage = 1

        # Runs perpetually until it receives the start scan message from the server (which would bring us to
        # scrape_stage = 2), or until the device is removed (which would bring us back to scrape_stage = 0)
        socketIO.on('start_scan', start_scan)
        while scrape_stage == 1:
            socketIO.wait(seconds=1)

        # If we successfully receive the start message from the front end
        if scrape_stage == 2:

            # Scrape Stage 3 - Scanning
            scrape_stage = 3

            # Initializes submit thread. Takes files added to list_to_submit array and submits them to AL server
            st = Thread(target=submit_thread, args=(terminal_id,), name="submit_thread")
            st.start()

            # Initializes receive thread. This thread listens for callbacks from the AL server
            rt = Thread(target=receive_thread, args=(terminal_id,), name="receive_thread")
            rt.start()


def start_scan(*args):
    global scrape_stage

    # Scrape Stage 2 - Credentials received; starting scan
    scrape_stage = 2


def check_done():
    """
    Called by our receive thread whenever it runs out of messages to report from the server. Checks if there are still
    partitions left to read, or files waiting to be submitted / received - if not, we know our scan is complete
    :return:
    """
    global socketIO
    global scrape_stage

    # Checks if all partitions have been mounted, all files from partitions have been ingested, and all our ingested
    # files have returned messages from the server. If all these are true then we are finished ingesting files and
    # our submit and receive threads are shut down. Once lists have been emitted they are reset.
    if partition_toread == 0 and len(list_to_submit) == 0 and len(list_to_receive) == 0 and scrape_stage == 3:

        # Scrape Stage 4 - Scan finished
        scrape_stage = 4
        time.sleep(0.1)
        socketIO.emit('be_device_event', 'done_loading', pass_files, mal_files)


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

            # Creates a new session
            Thread(target=session_login, name='session_login').start()

            # Makes new folder to hold partitions from this disk
            path_new = os.path.normpath('/tmp/imported_files' + device_id)
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
    elif action == 'remove' and device.get('DEVTYPE') == 'partition':
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

    while len(active_devices) != 0:

        # Waits until mount_lock is available (ie. other partitions have finished mounting)
        with mount_lock:

            # Makes sure device hasn't been unplugged while waiting
            if device_id in active_devices:

                # Mounts device
                os.system('sudo ~/al_scrape/bash_scripts/mount_block.sh ' + device_id +
                          ' /tmp/temp_device')

                # Makes new directory for this partition
                os.system('mkdir -p tmp/imported_files' + device_id)

                # Copies files directly into directory to be ingested
                os.system('cp -a /tmp/temp_device /tmp/imported_files' + device_id)

                # Removes Image
                os.system('sudo ~/al_scrape/bash_scripts/remove_dev_img.sh')

                # Unmounts device
                os.system('sudo ~/al_scrape/bash_scripts/unmount_block.sh /tmp/temp_device')

            time.sleep(3)
            # This partition is now finished; subtracts 1 from the partitions that need to be read and returns
            partition_toread -= 1

            return


def clear_files(device_id):
    """
    Called when all files from a partition have successfully been uploaded to Assemblyline, or when a device is
    removed from the terminal
    :return:
    """

    global active_devices, socketIO, scrape_stage, list_to_watch, dir_observer, partition_toread

    # Removes this partition from the array of currently connected devices
    if len(active_devices) != 0:
        active_devices.remove(device_id)

    # Removes the folder in imported_files containing the files corresponding to the removed device
    os.system('rm -rf /tmp/imported_files' + device_id)

    # If all devices have been removed, resets list and clears the imported files directory
    if len(active_devices) == 0:

        partition_toread = 0

        for directory in reversed(list_to_watch):
            time.sleep(0.1)
            try:
                dir_observer.remove_watch(directory)
                my_logger.info("Removed inotify watch on: " + directory)
            except Exception as e:
                my_logger.error("Could not remove watch on: " + directory)
        list_to_watch = []
        scrape_stage = 0
        socketIO.emit('be_device_event', 'disconnected')
        os.system('rm -rf /tmp/imported_files' + '/*')


# ============== Submit / Receive Assemblyline Server Functions ==============


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

    my_logger.info("Submit thread: begin")

    # Continuously monitors the list_to_submit. If a new entry is detected, uploads to server and deletes once done
    while 1 < scrape_stage < 4:

        # Begins to submit only if there are files to submit, and we are not in scrape stage 0 (ie. user credentials
        # have been entered)
        if len(list_to_submit):

            # Pops a file path from the list of files to be submitted
            ingest_path = list_to_submit.pop()

            # Checks to make sure the file at this path still exists
            if os.path.exists(ingest_path):

                # Checks if the file is empty; ingest is unable to examine empty files. Returns a warning if one is
                # submitted
                if os.stat(ingest_path).st_size != 0:
                    
                    # Outputs the name of file to be ingested to the front end
                    socketIO.emit("be_ingest_status", "submit_file", os.path.basename(ingest_path))

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
            time.sleep(1)

    my_logger.info("Submit thread: finished")


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

    my_logger.info("Receive thread: begin")

    while 1 < scrape_stage < 4:

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

                    score = msg['metadata']['al_score']
                    sid = msg['alert']['sid']
                    socketIO.emit("be_ingest_status", "receive_file", new_file)

                    if score >= 500:
                        mal_files.append(sid)

                    else:
                        pass_files.append(sid)

        else:
            check_done()
            time.sleep(1)

    my_logger.info("Receive thread: finished")


# ============== Initialization ==============

if __name__ == '__main__':

    # Creates directories to be used by our application to mount devices, and to hold files that are awaiting ingestion
    os.system('mkdir -p /tmp/temp_device')
    os.system('mkdir -p /tmp/imported_files')

    # Initializes application
    initialize()
