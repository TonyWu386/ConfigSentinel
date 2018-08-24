#--------------------------------------------------------
# ConfigSentinel v0.5
#
# Requires python3, python-daemon, inotify, ssmtp, and coreutils.
#
# Run as root. Ensure the working directory and DB file
# can only be modified by root.
#
# Copyright (c) 2018 [Tony Wu], All Right Reserved
#
# Email: xb.wu@mail.utoronto.ca
#
# Repo on GitHub and GitLab at TonyWu386/ConfigSentinel
#
# Licensed under the GNU GPL 3.0
#--------------------------------------------------------

from subprocess import Popen, PIPE, call
from sys import argv, exit
from pathlib import Path
from time import sleep
from signal import SIGTERM, SIGTSTP
from datetime import datetime
from lockfile import FileLock
from os import stat
from getopt import gnu_getopt, GetoptError
import sqlite3
import daemon
import inotify.adapters

# Set this to your own email for alerts (requires ssmtp/sendmail)
EMAIL = "nobody@localhost"

TEMPFILE = ".SenMail.txt"
CHECKSUMTOOL = "sha256sum"

# Ensure this directory exists and can only be modified by root (important)
WORKINGDIR = "/var/lib/configsentinel/"
DAEMONLOCK = "/var/run/sen.pid"

DBFILE = WORKINGDIR + "SenDB.db"
COMMANDFILE = WORKINGDIR + "Command.txt"
REFRESHFLAGFILE = WORKINGDIR + ".refresh"

DBCREATIONQUERY = "generateDB.sql"

INOTIFYIGNORE = ('IN_ACCESS', 'IN_OPEN', 'IN_CLOSE_NOWRITE')

# How many seconds between each requery
INTERVAL = 5

RESTOREDEFAULT = 1
EMAILDEFAULT = 0

EMAILSUBJECT = {"metadata": "File integrity failed - Metadata",
                "checksum": "File integrity failed - Checksum",
                "deletion": "File deletion detected",
                "modtime": "File modification time changed"}

exitFlag = False


def displayStatus():
    # Prints info about file enrollment

    if (not isEnvironmentValid()):
        return 1

    with sqlite3.connect(DBFILE) as conn:
        print("AutoRestore -- AutoEmail -- Degraded -- Path")
        print(('--------------------------------------------------------------'
               '------------------'))
        for row in conn.execute('''SELECT
                                Path,
                                AutoRestore,
                                AutoEmail,
                                Degraded
                                FROM Files;'''):
            path = row[0]
            autoRestore = row[1]
            autoEmail = row[2]
            degraded = row[3]
            print("{} -- {} -- {} -- {}"
                  .format(str(autoRestore), str(autoEmail),
                          str(degraded), path))
    return 0


def displayFileStatus():
    # Prints specific metadata about each file

    if (not isEnvironmentValid()):
        return 1

    with sqlite3.connect(DBFILE) as conn:
        print(('Checksum (' + CHECKSUMTOOL + ') -- Permission -- Owner:'
               'Group -- ModTime -- Path'))
        print(('--------------------------------------------------------------'
               '------------------'))
        for row in conn.execute('''SELECT
                                f.Path,            -- 0
                                f.GoodChecksum,    -- 1
                                d.FilePermission,  -- 2
                                d.FileOwner,       -- 3
                                d.FileGroup,       -- 4
                                d.FileModTime      -- 5
                                FROM Files as f
                                JOIN FileData as d
                                ON f.FileID == d.FileID;'''):
            path = row[0]
            goodChecksum = row[1]
            goodPermission = row[2]
            goodOwner = row[3]
            goodGroup = row[4]
            goodModTime = row[5]
            print("{}.. -- {} -- {}:{} -- {} -- {}"
                  .format(goodChecksum[:20], goodPermission, goodOwner,
                          goodGroup, goodModTime, path))
    return 0


def displayLog():
    # Prints event log

    if (not isEnvironmentValid()):
        return 1

    with sqlite3.connect(DBFILE) as conn:
        print("Timestamp -- Mismatch -- Path")
        print(('--------------------------------------------------------------'
               '------------------'))
        for row in conn.execute('''SELECT
                                f.Path,
                                l.Timestamp,
                                l.MismatchType
                                FROM Files as f
                                JOIN Logs as l
                                ON f.FileID == l.FileID;'''):
            path = row[0]
            timestamp = row[1]
            mismatchType = row[2]
            print("{} -- {} -- {}"
                  .format(str(timestamp), mismatchType, path))
    return 0


def displayInotifyLog():
    # Prints inotify log

    if (not isEnvironmentValid()):
        return 1

    print("Timestamp -- Raw")
    print(('--------------------------------------------------------------'
           '------------------'))
    with sqlite3.connect(DBFILE) as conn:
        for row in conn.execute('''SELECT
                        Timestamp,
                        Data
                        FROM InotifyEvent'''):
            timestamp = row[0]
            data = row[1]
            print("{} -- {}"
                  .format(str(timestamp), data))
    return 0


def sendEmail(content):
    # Send an alert email

    with open(TEMPFILE, 'w') as f:
        f.write(content)
    with open(TEMPFILE, 'r') as f:
        call(["sendmail", "-t"], stdin=f)
    Path(TEMPFILE).unlink()


def generateDB(inputFile, force):
    # Takes the path of an input file containing a list of full file paths.
    # One file path of each line.

    if (not Path(WORKINGDIR).is_dir()):
        print("Working directory " + WORKINGDIR + " does not exist")
        return 1

    if (not isFileSecure(WORKINGDIR)):
        return 1

    if (Path(DBFILE).is_file()):
        if (force):
            Path(DBFILE).unlink()
        else:
            print("DB file already exists")
            return 1

    if (not Path(inputFile).is_file()):
        print("Cannot access input file")
        return 1

    # Create DB and all required tables
    with sqlite3.connect(DBFILE) as conn:
        with open(DBCREATIONQUERY, 'r') as q:
            conn.executescript(q.read())

        # Populate basic file info and checksums
        with open(inputFile, 'r') as f:
            trackedFiles = f.read().rstrip().split("\n")
            if (len(set(trackedFiles)) != len(trackedFiles)):
                print("Duplicate files detected in input file")
                return 1
            for path in trackedFiles:
                if (Path(path).is_symlink()):
                    print("Symlinks are not supported: " + path)
                    Path(DBFILE).unlink()
                    return 1

                if (not Path(path).is_file()):
                    print("Not a valid file: " + path)
                    Path(DBFILE).unlink()
                    return 1

                pipe = Popen([CHECKSUMTOOL, path], stdout=PIPE)
                checksum = pipe.communicate()[0].decode('ascii').split(" ")[0]

                metadata = getFileMetadata(path)

                with open(path, 'rb') as f:
                    fileRawData = f.read()

                _createFileEntry(conn, path=path, checksum=checksum,
                                 metadata=metadata, fileRawData=fileRawData)

        conn.commit()

    call(["chmod", "600", DBFILE])

    return 0;


def enrollFile(path):
    # Enrolls a single file to be tracked

    if (Path(DBFILE).is_symlink()):
        print("Symlinks are not supported")
        return 1

    with sqlite3.connect(DBFILE) as conn:
        cur = conn.cursor()
        cur.execute('''SELECT COUNT(*) FROM Files WHERE Path = ?;''', (path,))
        if cur.fetchone()[0] != 0:
            print("File is already being tracked")
            return 1
        try:
            pipe = Popen([CHECKSUMTOOL, path], stdout=PIPE)
        except Exception:
            print("Cannot open file to be tracked: " + path)
            return 1
        checksum = pipe.communicate()[0].decode('ascii').split(" ")[0]

        metadata = getFileMetadata(path)

        with open(path, 'rb') as f:
            fileRawData = f.read()

        _createFileEntry(conn, path=path, checksum=checksum,
                         metadata=metadata, fileRawData=fileRawData)

        conn.commit()

        open(REFRESHFLAGFILE, 'w').close()

    return 0


def _recreateFile(conn, path, rawFileData, permission, fileOwner, fileGroup):
    # Fully recreates a file with metadata

    with open(path, 'wb') as f:
        f.write(rawFileData)

    _setFileMetadata(path=path, permission=permission,
                     fileOwner=fileOwner, fileGroup=fileGroup)

    _saveModTime(conn, path)


def _setFileMetadata(path, permission, fileOwner, fileGroup):
    call(["chown", "-h", (fileOwner + ":" + fileGroup), path])
    call(["chmod", permission, path])


def getFilePaths():
    filePaths = []
    with sqlite3.connect(DBFILE) as conn:
        for row in conn.execute('''SELECT Path FROM Files WHERE Degraded = 0;'''):
            filePaths.append(row[0])
    return filePaths


def performCheckAll():
    filePaths = getFilePaths()
    for path in filePaths:
        performCheck(path)


def performCheck(path):
    # Checks the file at the specified path and alters/restores if required
    # Returns 2 if inotify should be disabled,
    # 1 for found mismatch, 0 otherwise

    with sqlite3.connect(DBFILE) as conn:
        cur=conn.cursor()
        cur.execute('''SELECT
                    f.FileID,           -- 0
                    f.GoodChecksum,     -- 1
                    f.AutoRestore,      -- 2
                    f.AutoEmail,        -- 3
                    d.FilePermission,   -- 4
                    d.FileOwner,        -- 5
                    d.FileGroup,        -- 6
                    d.FileModTime,      -- 7
                    d.FileRawData       -- 8
                    FROM Files as f
                    JOIN FileData as d
                    ON f.FileID = d.FileID AND f.Path = ?;''',(path,))
        fileEntry = cur.fetchone()
        fileID = fileEntry[0]
        goodChecksum = fileEntry[1]
        autoRestore = fileEntry[2]
        autoEmail = fileEntry[3]
        goodPermission = fileEntry[4]
        goodFileOwner = fileEntry[5]
        goodFileGroup = fileEntry[6]
        goodModTime = fileEntry[7]
        goodRawData = fileEntry[8]

        if (not Path(path).is_file()):
            # This indicates a file has been deleted

            if (autoEmail):
                sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                            "\nSubject:" + EMAILSUBJECT["deletion"] + \
                            "\n\n" + path + "\n")

            _recordLogEntry(conn, fileID, "Deletion")
            conn.commit();

            if (autoRestore):
                _recreateFile(conn=conn,
                                path=path,
                                rawFileData=goodRawData,
                                permission=goodPermission,
                                fileOwner=goodFileOwner,
                                fileGroup=goodFileGroup)
                return 1
            else:
                # If not restored, a file is marked degraded and ignored
                _setFileDegraded(conn, fileID)
                return 2

        try:
            pipe = Popen([CHECKSUMTOOL, path], stdout=PIPE)
        except Exception as ex:
            print(ex)
            exit()

        currentChecksum = pipe.communicate()[0].decode('ascii')\
                        .split(" ")[0]

        currentMetadata = getFileMetadata(path)

        metadataMismatch = not ((currentMetadata["owner"] == goodFileOwner)
                    and (currentMetadata["group"] == goodFileGroup)
                    and (currentMetadata["permission"] == goodPermission))

        checksumMismatch = goodChecksum != currentChecksum

        modTimeMismatch = goodModTime != currentMetadata["modtime"]

        if (checksumMismatch):
            # Log and deal with bad data

            if (autoEmail):
                sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                            "\nSubject:" + EMAILSUBJECT["checksum"] + \
                            "\n\n" + path + "\n")

            _recordLogEntry(conn, fileID, "Checksum")

            with open(path, 'rb') as f:
                badRawData = f.read()

            conn.execute('''INSERT INTO BadFileRecord(
                    LogID,
                    BadChecksum,
                    BadRawData)
                    VALUES ((SELECT last_insert_rowid()), ?, ?);''',
                    (currentChecksum, sqlite3.Binary(badRawData)))

            if (autoRestore):
                _recreateFile(conn=conn,
                                path=path,
                                rawFileData=goodRawData,
                                permission=goodPermission,
                                fileOwner=goodFileOwner,
                                fileGroup=goodFileGroup)
                return 1

            else:
                # If not restored, a file is marked degraded and ignored
                _setFileDegraded(conn, fileID)
                return 2
            
        if (metadataMismatch):
            # Log and deal with bad metadata

            if (autoEmail):
                sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                            "\nSubject:" + EMAILSUBJECT["metadata"] + \
                            "\n\n" + path + "\n")

            _recordLogEntry(conn, fileID, "Metadata")

            conn.execute('''INSERT INTO BadMetadataRecord(
                    LogID,
                    BadOwner,
                    BadGroup,
                    BadPermission)
                    VALUES ((SELECT last_insert_rowid()), ?, ?, ?);''',
                    (currentMetadata["owner"],
                        currentMetadata["group"],
                        currentMetadata["permission"]))

            if (autoRestore):
                targetFile = Path(path)
                if (targetFile.is_symlink()):
                    targetFile.unlink()
                    _recreateFile(conn=conn,
                                    path=path,
                                    rawFileData=goodRawData,
                                    permission=goodPermission,
                                    fileOwner=goodFileOwner,
                                    fileGroup=goodFileGroup)
                else:
                    _setFileMetadata(path=path,
                                        permission=goodPermission,
                                        fileOwner=goodFileOwner,
                                        fileGroup=goodFileGroup)
                    _saveModTime(conn, path)
                return 1
            else:
                # If not restored, a file is marked degraded and ignored
                _setFileDegraded(conn, fileID)
                return 2

        if (modTimeMismatch):
            # File contents unchanged, but modification timestamp changed

            if (autoEmail):
                sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                            "\nSubject:" + EMAILSUBJECT["modtime"] + \
                            "\n\n" + path + "\n")

            _recordLogEntry(conn, fileID, "ModifyTime")
            _saveModTime(conn, path)

            return 1

        _recordLogEntry(conn, fileID, "_validate")

        return 0


def _createFileEntry(conn, path, checksum, metadata, fileRawData):

    conn.execute('''INSERT INTO Files(
        Path,
        GoodChecksum,
        AutoRestore,
        AutoEmail)
        VALUES (?, ?, ?, ?);''',
    (path,
    checksum,
    RESTOREDEFAULT,
    EMAILDEFAULT))

    conn.execute('''INSERT INTO FileData(
        FileID,
        FilePermission,
        FileOwner,
        FileGroup,
        FileModTime,
        FileRawData)
        VALUES ((SELECT last_insert_rowid()), ?, ?, ?, ?, ?);''',
    (metadata["permission"],
    metadata["owner"],
    metadata["group"],
    metadata["modtime"],
    sqlite3.Binary(fileRawData)))


def _setFileDegraded(conn, fileID):

    conn.execute('''UPDATE Files
                SET Degraded = 1
                WHERE FileID = ?;''',
                (fileID,))


def _recordLogEntry(conn, fileID, message):
    # Saves a mismatch event in the logs

    conn.execute('''INSERT INTO Logs(
        FileID,
        MismatchType)
        VALUES (?, ?);''',
        (fileID, message))


def _saveModTime(conn, path):
    # Saves the current modification time of the specified file

    currentMetadata = getFileMetadata(path)

    conn.execute('''UPDATE FileData
        SET FileModTime = ?
        WHERE FileID = (SELECT FileID FROM Files WHERE Path = ?);''',
                 (currentMetadata["modtime"], path))

def _RecordInotifyLog(data):

    with sqlite3.connect(DBFILE) as conn:
        conn.execute('''INSERT INTO InotifyEvent(
            Data)
            VALUES (?);''',
            (str(data),))


def getFileMetadata(path):
    # Takes path to a file or directory
    # Returns a dict with its metadata

    targetFile = Path(path)

    permission = str(oct(stat(path).st_mode))[-3:]

    return {"permission":permission,
            "owner":targetFile.owner(),
            "group":targetFile.group(),
            "modtime":str(round(targetFile.stat().st_mtime))}


def shutdown(signum, frame):
    # Responds to SIGTERM and SIGTSTP

    commandFile = Path(COMMANDFILE)
    if (commandFile.exists()):
        commandFile.unlink()
    global exitFlag
    exitFlag = True


def main():

    global exitFlag

    if (Path(COMMANDFILE).is_file()):
        exitFlag = True
        return

    open(COMMANDFILE, 'w').close()

    recheck = set()
    i = inotify.adapters.Inotify()
    filePaths = getFilePaths()
    for path in filePaths:
        i.add_watch(path)

    while (not exitFlag):
        inotifyEvents = i.event_gen(yield_nones=False, timeout_s=0.1)
        eventsOfNote = [(attr[2], attr[1]) for attr in inotifyEvents \
                        if attr[1][0] not in INOTIFYIGNORE]

        if (len(eventsOfNote)):
            _RecordInotifyLog(eventsOfNote)

        pathsToCheck = list(set([e[0] for e in eventsOfNote]).union(recheck))
        reloadNeeded = False

        newRecheck = set()
        for path in pathsToCheck:
            checkResult = performCheck(path)
            if (checkResult == 2):
                i.remove_watch(path)
            elif (checkResult == 1 or (path not in recheck)):
                reloadNeeded = True
                newRecheck.add(path)

        refreshFlag = Path(REFRESHFLAGFILE).is_file()
        recheck = newRecheck

        if (refreshFlag or reloadNeeded):
            i = inotify.adapters.Inotify()
            filePaths = getFilePaths()
            for path in filePaths:
                i.add_watch(path)
                recheck.add(path)
            if (refreshFlag):
                Path(REFRESHFLAGFILE).unlink()

        if (Path(COMMANDFILE).is_file()):
            with open(COMMANDFILE, 'w') as f:
                f.write("Daemon running!\nLast check " + \
                        str(datetime.now()) + "\n")

        timeToCheck = INTERVAL
        while (not(exitFlag) and timeToCheck > 0):
            if (not Path(COMMANDFILE).is_file()):
                exitFlag = True
            timeToCheck -= 1
            sleep(1)


def isFileSecure(path):
    # Returns true if give file or dir is properly locked down

    fileMetadata = getFileMetadata(path)
    if (fileMetadata["owner"] != "root"):
        print(path + " is not owned by root (this is very insecure)")
        return False
    if (fileMetadata["group"] != "root"):
        print(path + " does not belong to the root group")
        return False
    if (fileMetadata["permission"][-1] != "0"):
        print(path + "'s permission is insecure (last octal must be 0)")
        return False

    return True


def isEnvironmentValid():
    # Validates if the system is in a ready-to-run state

    if (INTERVAL < 1):
        print("Constant INTERVAL must NOT be less than 1")
        return False
    if (RESTOREDEFAULT not in (0, 1)):
        print("Constant AUTORESTOREDEFAULT must be 0 or 1")
        return False
    if (EMAILDEFAULT not in (0, 1)):
        print("Constant AUTOEMAILDEFAULT must be 0 or 1")
        return False
    if (not Path(DBFILE).is_file()):
        print("DB file does not exist")
        return False
    if (not isFileSecure(DBFILE)):
        return False
    if (not isFileSecure(WORKINGDIR)):
        return False

    return True


if __name__ == "__main__":

    try:
        optList = gnu_getopt(argv[1:],"fcg:d:l:e", ["force", "checkall",
                             "generate=", "daemon=", "log=", "enroll="])[0]
    except GetoptError as ex:
        print(ex)
        exit()

    if (len(optList) == 0):
        print("sen.py (--generate <filelist.txt> | --daemon (start | stop)" + \
              " | --log (status | files | event | inotify) | --checkall" + \
              " | --enroll <\"/path/to/file\">) [--force]")
        print("sen.py (-g <filelist.txt> | -d (start | stop) | " + \
              "-l (status | files | event | inotify)" + \
              " | -c | -e <\"/path/to/file\">) [-f]")
        exit()


    if (len(optList) > 1):
        if (optList[1][0] not in ("-f", "--force") or len(optList) > 2):
            print("Too many parameters provided")
            exit()


    force = False
    if (len(optList) == 2):
        force = (optList[1][0] in ("-f", "--force"))

    opt = optList[0]

    if (opt[0] in ("-l", "--log")):
        if (opt[1] == "status"):
            displayStatus()
        elif (opt[1] == "files"):
            displayFileStatus()
        elif (opt[1] == "event"):
            displayLog()
        elif (opt[1] == "inotify"):
            displayInotifyLog()
        else:
            print("Invalid option, expecting status | files | event | inotify")

    if (opt[0] in ("-c", "--checkall")):
        if (not isEnvironmentValid()):
            print("Not set up properly to perform manual check")
        else:
            if Path(COMMANDFILE).is_file():
                print("Daemon is currently running")
                print("Stop daemon before running manual check")
            else:
                performCheckAll()

    if (opt[0] in ("-d", "--daemon")):
        if (opt[1] == "start"):
            comFile = Path(COMMANDFILE)
            if (not isEnvironmentValid()):
                print("Not set up properly to start daemon")
            elif (comFile.exists()):
                print("Daemon is already running - cannot start")
            else:
                print("Starting up daemon...")
                with daemon.DaemonContext(
                        working_directory=WORKINGDIR,
                        pidfile=FileLock(DAEMONLOCK),
                        signal_map={
                                SIGTERM: shutdown,
                                SIGTSTP: shutdown}):
                    main()
        elif (opt[1] == "stop"):
            comFile = Path(COMMANDFILE)
            if (comFile.exists()):
                print("Daemon lock detected - signalling to stop")
                comFile.unlink()
            else:
                print("Daemon is not running")
        else:
            print("Invalid option, expecting start | stop")
            exit()

    if (opt[0] in ("-g", "--generate")):
        if (generateDB(opt[1], force) == 0):
            print("DB generation successful")
        else:
            print("DB generation failure")

    if (opt[0] in ("-e", "--enroll")):
        if (not Path(argv[2]).is_file()):
            print("Invalid file: " + argv[2])
        else:
            enrollFile(argv[2])
