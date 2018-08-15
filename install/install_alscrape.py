from installation_manager import Installer
import platform


def start():
    cur_os = platform.system().lower()

    if 'linux' in cur_os:

        installer = Installer('install_alscrape')

        installer.sudo_apt_get_install([
            'git',
            'python2.7',
            'python-pip'
        ])

        installer.upgrade_pip()

        installer.sudo_pip_install([
            'assemblyline-client==3.7.3',
            'cryptography==2.3',
            'flask==1.0.2',
            'inotify==0.2.9',
            'pyudev==0.21.0',
            'socketio==0.1.3',
            'socketio-client==0.7.2'
        ])

        installer.change_bash_priv()

        installer.make_service()

        installer.milestone('\r\n\r\nInstallation finished - AL Scrape is now running on this VM.\r\n')

    else:
        print
        print 'Error: AL Scrape must be installed on a VM running Ubuntu 16.04.x'
        exit(1)


if __name__ == '__main__':
    start()
