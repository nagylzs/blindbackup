
How to generate a key and a self signed certificate with one command

openssl req -x509 -newkey rsa:4096 -keyout key_pwd.pem -out cert.pem -days 3650
openssl rsa -in key_pwd.pem -out key.pem



  This is a minimalistic server-client pair that is able to backup your
  files securely.

  - Start your backup server on a computer. Backup server will hold
    backup files for clients.

  - On the client side, update settings.ini for your server.
    Then start backing up your files using backup.py (or backup.exe)

  Features/main goals:
  ====================

  - Designed for small portable applications stored on pendrives.
    The main goal is to be able to create backups securely for such
    sensitive data stored on a pendrive.
  - As simple as possible. Server configuration has total of 6 options
    to be configured.
  - Secure on the server side: only speaks HTTPS, uses
    Python/tornadoweb (no buffer underflow).
    
  - Secure for the client side:

        a.) Backed up files can be encrypted before sent to the server.
            Even if the server is exposed, only the client can decrypt
            the data!
        b.) By default, the backup server does not implement any
            function that could read data from the backed up files. Even
            if somebody gets his hands on your client program (including
            your password for the server!) he won't be able to retrieve
            any backups, simply because the server does not support
            restoring data from backups. Biggest threat: the attacker
            will be able to check if a given file exists on the server
            or not.
        c.) With a non-default configuration, the server can be used
            for directory synchronization and file data restoration.
            
  - Cross platform: works on Unix and Windows systems too on both
        32 and 64 bit architectures.
  - Client is totally portable. You can use this client on a pendrive
    to save data from your pendrive contents onto a remote server.
    Nothing is installed anywhere. You just remove the pendrive and
    there will be nothing on the computer that could be traced.
  - Client program has win32 and amd64 builds for Windows.
  - Portable server program win32 build is under development - use
    it as an application or as a win32 service.

