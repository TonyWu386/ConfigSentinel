# ConfigSentinel
Anti-tamper daemon for Linux

ConfigSentinel detects and responds to the alternation of files in a Linux environment.

This tool is able to enroll the status (content and metadata) for any number of files, and automatically detect alternations to them. It can respond by logging, sending an email alert, and/or restoring the file to the known good form.

Example use cases include users' .profile, .bashrc, and authorized_keys files. These and many other configuration files in Linux reside in the user's home folder are owned by that user. However, this leaves them open to tampering by any malicious code or actor running as that user. Since some of these files are basically shell scripts, this can lead to persistent malware without any root exploits.

python3 sen.py [generate filelist.txt] | [daemon] | [status] | [log] | [checkonce] | [daemonstop]

Basic Usage:

1) Put the full paths of files to track into a text file

2) Ensure the daemon's working directory exists and can only be modified by root (Default: "/var/lib/configsentinel/")

3) Enroll files using "generate filelist.txt"

4) Start the daemon using "daemon"

5) Stop the daemon either with "daemonstop" or SIGTERM

Requirements:

Linux

Root access

Python 3

python-daemon (for daemon mode)

ssmtp (for email alerts)

coreutils (sha256sum, chmod, etc)

This software is licensed under the GNU GPL 3.0

Copyright (c) 2018 [Tony Wu], All Right Reserved
