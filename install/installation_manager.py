import subprocess
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO)


def green(st):
    prefix = '\x1b[' + '32m'
    suffix = '\x1b[0m'
    return prefix + st + suffix


def red(st):
    prefix = '\x1b[' + '31m'
    suffix = '\x1b[0m'
    return prefix + st + suffix


def _runcmd(cmdline, shell=True, raise_on_error=True, piped_stdio=True, silent=False, cwd=None):
    if not silent:
        if not cwd:
            print "Running: %s" % cmdline
        else:
            print "Running: %s (%s)" % (cmdline, cwd)

    if piped_stdio:
        p = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell, cwd=cwd)
    else:
        p = subprocess.Popen(cmdline, shell=shell, cwd=cwd)

    stdout, stderr = p.communicate()
    rc = p.returncode
    if raise_on_error and rc != 0:
        raise Exception("FAILED: return_code:%s\nstdout:\n%s\nstderr:\n%s" % (rc, stdout, stderr))
    return rc, stdout, stderr


class Installer(object):

    def __init__(self, session_name):
        self.log = logging.getLogger(session_name)

    @staticmethod
    def runcmd(cmdline, shell=True, raise_on_error=True, piped_stdio=True, silent=False, cwd=None):
        return _runcmd(cmdline, shell, raise_on_error, piped_stdio, silent=silent, cwd=cwd)

    def milestone(self, s):
        self.log.info(green(s))

    def fatal(self, s):
        self.log.error(red(s))

    def sudo_apt_get_install(self, packages):
        cmd_line = ['sudo', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-y', '-q', 'install']

        if isinstance(packages, list):
            cmd_line.extend(packages)
            for package in packages:
                self.milestone('.....apt install:' + package)
        else:
            cmd_line.append(packages)
            self.milestone('.....apt install:' + packages)
        (_, _, _) = self.runcmd(cmd_line, shell=False)

    def sudo_pip_install(self, modules):
        cmd_line = ['sudo', '-H', 'pip', 'install']

        if isinstance(modules, list):
            cmd_line.extend(modules)
            for module in modules:
                self.milestone('.....pip install:' + module)
        else:
            cmd_line.append(modules)
            self.milestone('.....pip install:' + modules)
        (_, _, _) = self.runcmd(cmd_line, shell=False)

    def upgrade_pip(self):
        self.milestone('.....updating pip')
        self.runcmd('sudo -H pip install --upgrade pip')

    def setup_universe_repo(self):
        self.milestone('.....installing universe repo')
        self.runcmd('sudo apt-get install software-properties-common')
        self.runcmd('sudo apt-add-repository universe')
        self.runcmd('sudo apt-get update')

    def change_bash_priv(self):
        self.milestone('.....changing bash script privileges')
        self.runcmd('sudo chmod 700 /opt/al_scrape/bash_scripts/mount_block.sh')
        self.runcmd('sudo chmod 700 /opt/al_scrape/bash_scripts/unmount_block.sh')
        self.runcmd('sudo chown $USER /opt/al_scrape/bash_scripts/mount_block.sh')
        self.runcmd('sudo chown $USER /opt/al_scrape/bash_scripts/unmount_block.sh')

    def make_service(self):
        self.milestone('.....registering Al Scrape as a service')
        self.runcmd('sudo cp /opt/al_scrape/install/al_scrape.service /lib/systemd/system/al_scrape.service')
        self.runcmd('sudo systemctl daemon-reload', piped_stdio=False)
        self.runcmd('sudo systemctl enable al_scrape.service')
        self.runcmd('sudo systemctl start al_scrape.service')
