-- ConfigSentinel v0.5
-- Creates all required tables

CREATE TABLE Files (
    FileID            integer   PRIMARY KEY      NOT NULL,
    Path              text                       NOT NULL,
    GoodChecksum      text                       NOT NULL,
    Degraded          integer   DEFAULT 0        NOT NULL
        CHECK (Degraded = 0 OR Degraded = 1),
    AutoRestore       integer                    NOT NULL
        CHECK (AutoRestore = 0 OR AutoRestore = 1),
    AutoEmail         integer                    NOT NULL
        CHECK (AutoEmail = 0 OR AutoEmail = 1),
    UNIQUE (Path)
    );

CREATE TABLE Logs (
    LogID             integer   PRIMARY KEY      NOT NULL,
    FileID            integer                    NOT NULL,
    MismatchType      text                       NOT NULL,
    Timestamp         datetime  DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(FileID) REFERENCES Files(FileID)
    );

CREATE TABLE BadFileRecord (
    BadFileRecordID   integer   PRIMARY KEY      NOT NULL,
    LogID             integer                    NOT NULL,
    BadChecksum       text                       NOT NULL,
    BadRawData        text                       NOT NULL,
    FOREIGN KEY(LogID) REFERENCES Logs(LogID)
    );

CREATE TABLE BadMetadataRecord (
    BadMetadataRecordID  integer  PRIMARY KEY    NOT NULL,
    LogID                integer                 NOT NULL,
    BadOwner             text                    NOT NULL,
    BadGroup             text                    NOT NULL,
    BadPermission        text                    NOT NULL,
    FOREIGN KEY(LogID) REFERENCES Logs(LogID)
    );

CREATE TABLE FileData (
    FileID            integer   PRIMARY KEY      NOT NULL,
    FilePermission    text                       NOT NULL,
    FileOwner         text                       NOT NULL,
    FileGroup         text                       NOT NULL,
    FileModTime       text                       NOT NULL,
    FileRawData       blob                       NOT NULL,
    FOREIGN KEY(FileID) REFERENCES Files(FileID)
        ON DELETE RESTRICT
    );

CREATE TABLE InotifyEvent (
    EventID           integer   PRIMARY KEY      NOT NULL,
    timestamp         datetime  DEFAULT CURRENT_TIMESTAMP,
    Data              text                       NOT NULL
    );

CREATE UNIQUE INDEX idx_Files_FileID ON Files (FileID);
CREATE UNIQUE INDEX idx_Logs_LogID ON Logs (LogID);
