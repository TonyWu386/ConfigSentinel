#--------------------------------------------------------
# ConfigSentinel v0.1
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
import sqlite3
import daemon

# Set this to your own email for alerts (requires ssmtp/sendmail)
EMAIL = "nobody@localhost"

TEMPFILE = ".SenMail.txt"
CHECKSUMTOOL = "sha256sum"

# Ensure this directory exists and can only be modified by root (important)
WORKINGDIR = "/var/lib/configsentinel/"

DBFILE = WORKINGDIR + "SenDB.db"
COMMANDFILE = WORKINGDIR + "Command.txt"

# How many seconds between each rescan
INTERVAL = 30

AUTORESTOREDEFAULT = 1
AUTOEMAILDEFAULT = 0

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
            FileID integer PRIMARY KEY,
            Path text,
            GoodChecksum text,
            Degraded integer DEFAULT 0,
            AutoRestore integer DEFAULT {},
            AutoEmail integer DEFAULT {}
            );'''.format(AUTORESTOREDEFAULT, AUTOEMAILDEFAULT))

        conn.execute('''CREATE TABLE Logs (
            LogID integer PRIMARY KEY,
            FileID integer,
            MismatchType text,
            Timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(FileID) REFERENCES Files(FileID)
            );''')

        conn.execute('''CREATE TABLE BadFileRecord (
            BadFileRecordID integer PRIMARY KEY,
            LogID integer,
            BadChecksum text,
            BadRawData text,
            FOREIGN KEY(LogID) REFERENCES Logs(LogID)
            );''')

        conn.execute('''CREATE TABLE BadMetadataRecord (
            BadMetadataRecordID integer PRIMARY KEY,
            LogID integer,
            BadOwner,
            BadGroup,
            BadPermission,
            FOREIGN KEY(LogID) REFERENCES Logs(LogID)
            );''')

        conn.execute('''CREATE TABLE FileData (
            FileID integer PRIMARY KEY,
            Permission text,
            FileOwner text,
            FileGroup text,
            FileRawData blob,
            FOREIGN KEY(FileID) REFERENCES Files(FileID)
            );''')

        # Populate basic file info and checksums
        with open(inputFile, 'r') as f:
            trackedFiles = f.read().rstrip().split("\n")
            for file in trackedFiles:
                try:
                    pipe = Popen([CHECKSUMTOOL, file], stdout=PIPE)
                except Exception:
                    print("Cannot open file to be tracked: " + file + "\n")
                    call(["rm", TEMPFILE])
                    return 1
                checksum = pipe.communicate()[0].decode('ascii').split(" ")[0]
                conn.execute('''INSERT INTO Files(
                        Path,
                        GoodChecksum)
                        VALUES (?, ?);''', (file, checksum))

        # Populate metadata
        for row in conn.execute("SELECT FileID, Path FROM Files;"):
            (fileID, path) = (row[0], row[1])
            pipe = Popen(["ls", "-l", path], stdout=PIPE)
            fileInfo = pipe.communicate()[0].decode('ascii').split(" ")

            pipe = Popen(["stat", "-c", "\"%a\"", path], stdout=PIPE)
            permission = pipe.communicate()[0].decode('ascii')\
                        .rstrip().replace("\"","")

            with open(path, 'rb') as f:
                fileRawData = f.read()

            conn.execute('''INSERT INTO FileData(
                          FileID,
                          Permission,
                          FileOwner,
                          FileGroup,
                          FileRawData) VALUES (?, ?, ?, ?, ?);''',
            (fileID,
             permission,
             fileInfo[2],
             fileInfo[3],
             sqlite3.Binary(fileRawData)))

        conn.commit()
        return 0;


def recreateFile(path, rawFileData, permission, fileOwner, fileGroup):
    # Fully recreates a file with metadata

    with open(path, 'wb') as f:
        f.write(rawFileData)

    call(["chown", (fileOwner + ":" + fileGroup), path])
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
                              "\nSubject:File missing\n\n")
                continue


            try:
                pipe = Popen([CHECKSUMTOOL, path], stdout=PIPE)
            except Exception as ex:
                print(ex)
                exit()

            currentChecksum = pipe.communicate()[0].decode('ascii')\
                            .split(" ")[0]


            pipe = Popen(["ls", "-l", path], stdout=PIPE)
            fileInfo = pipe.communicate()[0].decode('ascii').split(" ")

            pipe = Popen(["stat", "-c", "\"%a\"", path], stdout=PIPE)
            currentPermission = pipe.communicate()[0].decode('ascii')\
                        .rstrip().replace("\"","")

            (currentOwner, currentGroup) = (fileInfo[2], fileInfo[3])

            metadataMismatch = not ((currentOwner == goodFileOwner) and \
                                    (currentGroup == goodFileGroup) and \
                                    (currentPermission == goodPermission))

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
                        (currentOwner, currentGroup, currentPermission))

                if (autoRestore == 1):
                    call(["chown", (goodFileOwner + ":" + goodFileGroup),
                          path])
                    call(["chmod", goodPermission, path])
                else:
                    # If not restored, a file is marked degraded and ignored
                    conn.execute('''UPDATE Files
                                 SET Degraded = 1
                                 WHERE FileID = ?;''',
                                 (fileID))
                conn.commit();


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
                    cur = conn.cursor()
                    cur.execute('''SELECT
                                Permission,  -- 0
                                FileOwner,   -- 1
                                FileGroup,   -- 2
                                FileRawData  -- 3
                                FROM FileData WHERE FileID = ?;''',
                                (fileID,))

                    fileData = cur.fetchone()
                    permission = fileData[0]
                    fileOwner = fileData[1]
                    fileGroup = fileData[2]
                    rawFileData = fileData[3]

                    recreateFile(path=path, rawFileData=rawFileData,
                                 permission=permission, fileOwner=fileOwner,
                                 fileGroup=fileGroup)

                else:
                    # If not restored, a file is marked degraded and ignored
                    conn.execute('''UPDATE Files
                                 SET Degraded = 1
                                 WHERE FileID = ?;''',
                                 (fileID))

                conn.commit();

            if (checksumMismatch or metadataMismatch):
                if (autoEmail == 1):
                    sendEmail("To:" + EMAIL + "\nFrom:" + EMAIL + \
                              "\nSubject:File integrity failed\n\n")


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
    global exitFlag
    exitFlag = 1


def main():
    global exitFlag
    exitFlag = 0
    with open(COMMANDFILE, 'w') as f:
        f.write("Daemon started!")

    while (exitFlag == 0):
        performCheck()
        timeToCheck = INTERVAL
        while (exitFlag == 0 and timeToCheck > 0):
            if (not Path(COMMANDFILE).is_file()):
                exitFlag = 1
            timeToCheck -= 1
            sleep(1)


if __name__ == "__main__":
    if (len(argv) == 1):
        print("sen.py [generate filelist.txt] | [daemon] | [status] " + \
              "| [log] | [checkonce] | [daemonstop]")
        exit()

    if (len(argv) == 2):
        if (argv[1] == "status"):
            displayStatus()
        elif (argv[1] == "log"):
            displayLog()
        elif (argv[1] == "checkonce"):
            if (not Path(DBFILE).is_file()):
                print("Cannot perform one-time check: DB file does not exist")
            else:
                performCheck()
        elif (argv[1] == "daemonstop"):
            call(["rm", "-f", COMMANDFILE])
        elif (argv[1] == "daemon"):
            if (not Path(DBFILE).is_file()):
                print("Cannot start daemon: DB file does not exist")
            print("Starting up daemon...")
            with daemon.DaemonContext(
                    working_directory=WORKINGDIR,
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
        else:
            print("Unrecognized command")
        exit()
