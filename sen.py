#--------------------------------------------------------
# ConfigSentinel v0.3
#
# Requires python3, python-daemon, ssmtp, and coreutils.
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
import sqlite3
import daemon

# Set this to your own email for alerts (requires ssmtp/sendmail)
EMAIL = "nobody@localhost"

TEMPFILE = ".SenMail.txt"
CHECKSUMTOOL = "sha256sum"

# Ensure this directory exists and can only be modified by root (important)
WORKINGDIR = "/var/lib/configsentinel/"
DAEMONLOCK = "/var/run/sen.pid"

DBFILE = WORKINGDIR + "SenDB.db"
COMMANDFILE = WORKINGDIR + "Command.txt"

# How many seconds between each rescan
INTERVAL = 30

AUTORESTOREDEFAULT = 1
AUTOEMAILDEFAULT = 0

EMAILSUBJECT = {"metadata": "File integrity failed - Metadata",
                "checksum": "File integrity failed - Checksum",
                "deletion": "File deletion detected"}

exitFlag = 0


def sendEmail(content):
    # Send an alert email

    with open(TEMPFILE, 'w') as f:
        f.write(content)
    with open(TEMPFILE, 'r') as f:
        call(["sendmail", "-t"], stdin=f)
    call(["rm", TEMPFILE])


def generateDB(inputFile):
    # Takes the path of an input file containing a list of full file paths.
    # One file path of each line.

    if (not Path(WORKINGDIR).is_dir()):
        print("Working directory " + WORKINGDIR + " does not exist")
        return 1

    if (Path(DBFILE).is_file()):
        print("DB file already exists")
        return 1

    if (not Path(inputFile).is_file()):
        print("Cannot access input file")
        return 1

    # Create DB and all required tables
    with sqlite3.connect(DBFILE) as conn:
        conn.execute('''CREATE TABLE Files (
            FileID        integer  PRIMARY KEY  NOT NULL,
            Path          text                  NOT NULL,
            GoodChecksum  text                  NOT NULL,
            Degraded      integer  DEFAULT 0    NOT NULL,
            AutoRestore   integer  DEFAULT {}   NOT NULL,
            AutoEmail     integer  DEFAULT {}   NOT NULL,
            UNIQUE (Path)
            );'''.format(AUTORESTOREDEFAULT, AUTOEMAILDEFAULT))

        conn.execute('''CREATE TABLE Logs (
            LogID         integer   PRIMARY KEY  NOT NULL,
            FileID        integer                NOT NULL,
            MismatchType  text                   NOT NULL,
            Timestamp     datetime  DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(FileID) REFERENCES Files(FileID)
            );''')

        conn.execute('''CREATE TABLE BadFileRecord (
            BadFileRecordID  integer  PRIMARY KEY  NOT NULL,
            LogID            integer               NOT NULL,
            BadChecksum      text                  NOT NULL,
            BadRawData       text                  NOT NULL,
            FOREIGN KEY(LogID) REFERENCES Logs(LogID)
            );''')

        conn.execute('''CREATE TABLE BadMetadataRecord (
            BadMetadataRecordID  integer  PRIMARY KEY  NOT NULL,
            LogID                integer               NOT NULL,
            BadOwner             text                  NOT NULL,
            BadGroup             text                  NOT NULL,
            BadPermission        text                  NOT NULL,
            FOREIGN KEY(LogID) REFERENCES Logs(LogID)
            );''')

        conn.execute('''CREATE TABLE FileData (
            FileID           integer  PRIMARY KEY  NOT NULL,
            Permission       text                  NOT NULL,
            FileOwner        text                  NOT NULL,
            FileGroup        text                  NOT NULL,
            FileRawData      blob                  NOT NULL,
            FOREIGN KEY(FileID) REFERENCES Files(FileID)
            );''')

        # Populate basic file info and checksums
        with open(inputFile, 'r') as f:
            trackedFiles = f.read().rstrip().split("\n")
            if (len(set(trackedFiles)) != len(trackedFiles)):
                print("Duplicate files detected in input file")
                return 1
            for file in trackedFiles:
                if (Path(file).is_symlink()):
                    print("Symlinks are not supported")
                    return 1
                try:
                    pipe = Popen([CHECKSUMTOOL, file], stdout=PIPE)
                except Exception:
                    print("Cannot open file to be tracked: " + file)
                    call(["rm", DBFILE])
                    return 1
                checksum = pipe.communicate()[0].decode('ascii').split(" ")[0]
                conn.execute('''INSERT INTO Files(
                        Path,
                        GoodChecksum)
                        VALUES (?, ?);''', (file, checksum))

        # Populate metadata
        for row in conn.execute("SELECT FileID, Path FROM Files;"):
            (fileID, path) = (row[0], row[1])
                        
            metadata = getFileMetadata(path)

            with open(path, 'rb') as f:
                fileRawData = f.read()

            conn.execute('''INSERT INTO FileData(
                          FileID,
                          Permission,
                          FileOwner,
                          FileGroup,
                          FileRawData) VALUES (?, ?, ?, ?, ?);''',
            (fileID,
             metadata["permission"],
             metadata["owner"],
             metadata["group"],
             sqlite3.Binary(fileRawData)))

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

        conn.execute('''INSERT INTO Files(
                Path,
                GoodChecksum)
                VALUES (?, ?);''',
        (path,
         checksum))

        conn.execute('''INSERT INTO FileData(
                FileID,
                Permission,
                FileOwner,
                FileGroup,
                FileRawData)
                VALUES ((SELECT last_insert_rowid()), ?, ?, ?, ?);''',
        (metadata["permission"],
         metadata["owner"],
         metadata["group"],
         sqlite3.Binary(fileRawData)))

        conn.commit()

    return 0


def recreateFile(path, rawFileData, permission, fileOwner, fileGroup):
    # Fully recreates a file with metadata

    with open(path, 'wb') as f:
        f.write(rawFileData)

    call(["chown", "-h", (fileOwner + ":" + fileGroup), path])
    call(["chmod", permission, path])


def performCheck():
    # Assumes the DB has already been created
    # Runs a round of checks, and triggers alters/restores

    with sqlite3.connect(DBFILE) as conn:
        for row in conn.execute('''SELECT
                                f.FileID,       -- 0
                                f.Path,         -- 1
                                f.GoodChecksum, -- 2
                                f.AutoRestore,  -- 3
                                f.AutoEmail,    -- 4
                                d.Permission,   -- 5
                                d.FileOwner,    -- 6
                                d.FileGroup,    -- 7
                                d.FileRawData   -- 8
                                FROM Files as f
                                JOIN FileData as d
                                ON f.FileID = d.FileID AND f.Degraded = 0;'''):
            fileID = row[0]
            path = row[1]
            goodChecksum = row[2]
            autoRestore = row[3]
            autoEmail = row[4]
            goodPermission = row[5]
            goodFileOwner = row[6]
            goodFileGroup = row[7]
            goodRawData = row[8]

            if (not Path(path).is_file()):
                # This indicates a file has been deleted

                conn.execute('''INSERT INTO Logs(
                        FileID,
                        MismatchType)
                        VALUES (?, ?);''',
                        (fileID, "Deletion"))
                conn.commit();

                if (autoRestore == 1):
                    recreateFile(path=path, rawFileData=goodRawData,
                                 permission=goodPermission,
                                 fileOwner=goodFileOwner,
                                 fileGroup=goodFileGroup)
                else:
                    # If not restored, a file is marked degraded and ignored
                    conn.execute('''UPDATE Files
                                 SET Degraded = 1
                                 WHERE FileID = ?;''',
                                 (fileID))

                if (autoEmail == 1):
                    sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                              "\nSubject:" + EMAILSUBJECT["deletion"] + \
                              "\n\n" + path + "\n")
                continue


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

            if (metadataMismatch):
                # Log and deal with bad metadata

                conn.execute('''INSERT INTO Logs(
                        FileID,
                        MismatchType)
                        VALUES (?, ?);''',
                        (fileID, "Metadata"))

                conn.execute('''INSERT INTO BadMetadataRecord(
                        LogID,
                        BadOwner,
                        BadGroup,
                        BadPermission)
                        VALUES ((SELECT last_insert_rowid()), ?, ?, ?);''',
                        (currentMetadata["owner"],
                         currentMetadata["group"],
                         currentMetadata["permission"]))

                if (autoRestore == 1):
                    targetFile = Path(path)
                    if (targetFile.is_symlink()):
                        targetFile.unlink()
                        recreateFile(path=path, rawFileData=goodRawData,
                            permission=goodPermission, fileOwner=goodFileOwner,
                            fileGroup=goodFileGroup)
                    else:
                        call(["chown", "-h",
                              (goodFileOwner + ":" + goodFileGroup), path])
                        call(["chmod", goodPermission, path])
                else:
                    # If not restored, a file is marked degraded and ignored
                    conn.execute('''UPDATE Files
                                 SET Degraded = 1
                                 WHERE FileID = ?;''',
                                 (fileID))
                conn.commit();

                if (autoEmail == 1):
                    sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                              "\nSubject:" + EMAILSUBJECT["metadata"] + \
                              "\n\n" + path + "\n")


            if (checksumMismatch):
                # Log and deal with bad data

                conn.execute('''INSERT INTO Logs(
                        FileID,
                        MismatchType)
                        VALUES (?, ?);''',
                        (fileID, "Checksum"))

                with open(path, 'rb') as f:
                    badRawData = f.read()

                conn.execute('''INSERT INTO BadFileRecord(
                        LogID,
                        BadChecksum,
                        BadRawData)
                        VALUES ((SELECT last_insert_rowid()), ?, ?);''',
                        (currentChecksum, sqlite3.Binary(badRawData)))

                if (autoRestore == 1):
                    recreateFile(path=path, rawFileData=goodRawData,
                                 permission=goodPermission,
                                 fileOwner=goodFileOwner,
                                 fileGroup=goodFileGroup)

                else:
                    # If not restored, a file is marked degraded and ignored
                    conn.execute('''UPDATE Files
                                 SET Degraded = 1
                                 WHERE FileID = ?;''',
                                 (fileID))

                conn.commit();

                if (autoEmail == 1):
                    sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                              "\nSubject:" + EMAILSUBJECT["checksum"] + \
                              "\n\n" + path + "\n")


def displayStatus():

    if (not Path(DBFILE).is_file()):
        print("DB file has not been generated")
        return 1

    with sqlite3.connect(DBFILE) as conn:
        print("AutoRestore -- AutoEmail -- Degraded -- Path")
        print("-------------------------------------------------------------")
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
            print(str(autoRestore) + "           -- " + str(autoEmail) + \
                  "         -- " + str(degraded) + "        --  " + path)
    return 0


def displayLog():

    if (not Path(DBFILE).is_file()):
        print("DB file has not been generated")
        return 1

    with sqlite3.connect(DBFILE) as conn:
        print("Timestamp            --  Mismatch  --  Path")
        print("-------------------------------------------------------------")
        for row in conn.execute('''SELECT
                                f.Path,
                                l.Timestamp,
                                l.MismatchType
                                FROM Files as f
                                JOIN Logs as l
                                ON f.FileID == l.FileID;'''):
            (path, timestamp, mismatchType) = (row[0], row[1], row[2])
            print(str(timestamp) + "  --  " + str(mismatchType) + \
                  "  --  " + path)
        return 0


def shutdown(signum, frame):
    # Responds to SIGTERM and SIGTSTP

    commandFile = Path(COMMANDFILE)
    if (commandFile.exists()):
        commandFile.unlink()
    global exitFlag
    exitFlag = 1


def main():

    global exitFlag

    if (Path(DAEMONLOCK).is_file()):
        exitFlag = 1

    while (exitFlag == 0):
        performCheck()
        with open(COMMANDFILE, 'w') as f:
            f.write("Daemon running!\nLast check " + str(datetime.now()))
        timeToCheck = INTERVAL
        while (exitFlag == 0 and timeToCheck > 0):
            if (not Path(COMMANDFILE).is_file()):
                exitFlag = 1
            timeToCheck -= 1
            sleep(1)


def getFileMetadata(path):
    # Give the path to a file, return a dict with its metadata

    targetFile = Path(path)

    permission = str(oct(stat(path).st_mode))[-3:]

    return {"permission":permission, "owner":targetFile.owner(),
            "group":targetFile.group()}


def validateEnvironment():
    # Validates if the system is in a ready-to-run state

    if (INTERVAL < 1):
        print("Constant INTERVAL must NOT be less than 1")
        return 1
    if (AUTORESTOREDEFAULT not in (0, 1)):
        print("Constant AUTORESTOREDEFAULT must be 0 or 1")
        return 1
    if (AUTOEMAILDEFAULT not in (0, 1)):
        print("Constant AUTOEMAILDEFAULT must be 0 or 1")
        return 1
    if (not Path(DBFILE).is_file()):
        print("DB file does not exist")
        return 1

    dbFileMetadata = getFileMetadata(DBFILE)
    if (dbFileMetadata["owner"] != "root"):
        print("DB file is not owned by root (this is very insecure)")
        return 1
    if (dbFileMetadata["group"] != "root"):
        print("DB file is not in the root group")
        return 1
    if (dbFileMetadata["permission"][-1] != "0"):
        print("DB file's permission is insecure (last digit must be 0)")
        return 1

    return 0


if __name__ == "__main__":
    if (len(argv) == 1):
        print("sen.py [generate filelist.txt] | [daemon] | [status] " + \
              "| [log] | [checkonce] | [daemonstop] | " + \
              "[enroll \"/path/to/file\"]")
        exit()

    if (len(argv) == 2):
        if (argv[1] == "status"):
            displayStatus()
        elif (argv[1] == "log"):
            displayLog()
        elif (argv[1] == "checkonce"):
            if (validateEnvironment() != 0):
                print("Cannot perform one-time check")
            else:
                performCheck()
        elif (argv[1] == "daemonstop"):
            commandFile = Path(COMMANDFILE)
            if (commandFile.exists()):
                print("Signalling daemon to stop")
                commandFile.unlink()
            else:
                print("Daemon is not running")
        elif (argv[1] == "daemon"):
            commandFile = Path(COMMANDFILE)
            if (validateEnvironment() != 0):
                print("Cannot start daemon")
            elif (commandFile.exists()):
                print("Daemon is already running")
            else:
                print("Starting up daemon...")
                with daemon.DaemonContext(
                        working_directory=WORKINGDIR,
                        pidfile=FileLock(DAEMONLOCK),
                        signal_map={
                                SIGTERM: shutdown,
                                SIGTSTP: shutdown}):
                    main()
        else:
            print("Unrecognized command")
        exit()

    if (len(argv) == 3):
        if (argv[1] == "generate"):
            if (generateDB(argv[2]) == 0):
                print("DB generation successful")
            else:
                print("DB generation failure")
        elif (argv[1] == "enroll"):
            if (not Path(argv[2]).is_file()):
                print("Invalid file: " + argv[2])
            else:
                enrollFile(argv[2])
        else:
            print("Unrecognized command")
        exit()
