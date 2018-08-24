# ConfigSentinel
Anti-tamper daemon for Linux

Version 0.5

ConfigSentinel detects and responds to the alternation of files in a Linux environment.

This tool is able to enroll the status (content and metadata) for any number of files, and automatically detect alternations to them. Inotify is used to discover changes, with additional checks on the files to clarify the alternation. The tool can respond by logging, sending an email alert, and/or restoring the file to the known good form.

Example use cases include users' .profile, .bashrc, and authorized_keys files. These and many other configuration files in Linux reside in the user's home folder are owned by that user. However, this leaves them open to tampering by any malicious code or actor running as that user. Since some of these files are basically shell scripts, this can lead to persistent malware without any root exploits.


python3 sen.py (--generate <filelist.txt> | --daemon (start | stop) | --log (status | files | event | inotify) | --checkall | --enroll <"/path/to/file">) [--force]

python3 sen.py (-g <filelist.txt> | -d (start | stop) | -l (status | files | event | inotify) | -c | -e <"/path/to/file">) [-f]

"--force" can be used with "--generate" to overwrite any existing DB files.

"--checkall" runs a full scan of every file enrolled in the system. It can only be ran while the daemon is stopped, to avoid race conditions.

Basic Usage:

1) Put the full paths of files to track into a text file

2) Ensure the daemon's working directory exists and can only be modified by root (Default: "/var/lib/configsentinel/")

3) Enroll files using "--generate filelist.txt"

4) Start the daemon using "--daemon start"

5) Stop the daemon either with "--daemon stop" or SIGTERM

Requirements:

Linux

Root access

Python 3

> python library: python-daemon (for daemon mode)

> python library: inotify (for daemon mode)

ssmtp (for email alerts)

coreutils (sha256sum, chmod, etc)

This software is licensed under the GNU GPL 3.0

Copyright (c) 2018 [Tony Wu], All Right Reserved
