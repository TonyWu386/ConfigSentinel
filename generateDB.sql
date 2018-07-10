-- ConfigSentinel v0.4
-- Creates all required tables

CREATE TABLE Files (
    FileID            integer   PRIMARY KEY      NOT NULL,
    Path              text                       NOT NULL,
    GoodChecksum      text                       NOT NULL,
    Degraded          integer   DEFAULT 0        NOT NULL,
    AutoRestore       integer                    NOT NULL,
    AutoEmail         integer                    NOT NULL,
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
    );
