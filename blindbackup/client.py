#!/usr/bin/env python3
import copy
import io
import json
import os.path
import pycurl
import threading
import urllib.parse

from blindbackup import cryptfile
from blindbackup.syncdir import FsProvider, FsListener
from blindbackup.util import localpath, create_tmp_file_for


# Should look at here:
# https://pypi.python.org/pypi/watchdog

#        self.output.write(struct.pack(">Bi",TYP_INT,size))
#        size = struct.unpack(">i",self.input.read(4))[0]





def create_client(settings):
    certfile = localpath(settings, "ssl_certfile", None)
    return Client(
        settings["server_url"], certfile,
        settings["login"], settings["password"])


class ReqError(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


class Client:
    """Use this client class to communicate with the BlindBackup server."""

    def __init__(self, server_url, server_crt, login, pwd):
        self.server_url = server_url
        self.server_crt = server_crt
        self.login = login
        self.pwd = pwd

    def _curl(self, url, percentfunc):
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.USERAGENT, "BlindBackup v1.0")
        if self.server_crt:
            curl.setopt(pycurl.SSL_VERIFYPEER, 1)
            curl.setopt(pycurl.SSL_VERIFYHOST, 2)
            curl.setopt(pycurl.CAINFO, self.server_crt)
        else:
            curl.setopt(pycurl.SSL_VERIFYPEER, 0)
            curl.setopt(pycurl.SSL_VERIFYHOST, 0)

        self.percent_up, self.percent_down = 0.0, 0.0
        self.percentfunc = percentfunc
        curl.setopt(curl.NOPROGRESS, 0)
        curl.setopt(curl.PROGRESSFUNCTION, self._progress)

        return curl

    @classmethod
    def _perform(cls, curl):
        e = io.BytesIO()
        curl.setopt(curl.WRITEFUNCTION, e.write)
        curl.perform()
        status = curl.getinfo(pycurl.HTTP_CODE)
        curl.close()
        if status != 200:
            e_value = e.getvalue().decode("UTF-8")
            try:
                e_value = json.loads(e_value)
            except:
                pass
            raise ReqError(status, e_value)
        else:
            return e.getvalue()

    def _progress(self, download_t, download_d, upload_t, upload_d):
        if upload_t:
            percent_up = round(100.0 * upload_d / upload_t, 1)
        else:
            percent_up = 0.0
        if download_t:
            percent_down = round(100.0 * download_d / download_t, 1)
        else:
            percent_down = 0.0
        if percent_down != self.percent_down or percent_up != self.percent_up:
            self.percent_up = percent_up
            self.percent_down = percent_down
            if self.percentfunc:
                self.percentfunc(percent_up, percent_down)

    def _get(self, getparams, percentfunc=None):
        """GET data from server.

        @param getparams: a list of (fname,value) tuples, passed as
            GET parameters.
        """
        return self._perform(
            self._curl(
                self.server_url + "?" + urllib.parse.urlencode(getparams),
                percentfunc
            )
        )

    def _post(self, getparams, postvalues, files=None, percentfunc=None):
        """POST data to server.

        @param getparams: a list of (fname,value) tuples, passed as
            GET parameters.
        @param postvalues: a list of (fname,value) tuples, passed as
            POST parameters.
        @param files: a list of (fname,fpath) tuples, passed as
            multipart form data.
        @param percentfunc: If given, this should be:

            def progress_percent(percent_up,percent_down)
        """
        c = self._curl(
            self.server_url + "?" + urllib.parse.urlencode(getparams),
            percentfunc
        )
        c.setopt(c.POST, 1)
        # http://code.activestate.com/recipes/576422/
        # http://pycurl.cvs.sourceforge.net/pycurl/pycurl/tests/test_post2.py?view=markup
        # http://stackoverflow.com/questions/679966/problem-with-python-curl-while-submitting-file
        # FORM_BUFFER FORM_BUFFERPTR FORM_CONTENTS FORM_CONTENTTYPE
        # FORM_FILE FORM_FILENAME
        # Took me an hour to figure this out! :-(
        filevalues = []
        if files:
            for fname, fpath in files:
                filevalues.append((
                    fname.encode("UTF-8"), (
                        c.FORM_FILENAME, os.path.split(fpath)[1].encode("UTF-8"),
                        c.FORM_FILE, fpath.encode("UTF-8"),
                        # c.FORM_CONTENTTYPE,"application/octet-stream"
                    )
                ))
        c.setopt(c.HTTPPOST, postvalues + filevalues)
        return self._perform(c)

    def _initparams(self, action, **kwargs):
        """Initialize parameters for an action."""
        res = copy.copy(kwargs)
        res.update({
            "login": self.login,
            "pwd": self.pwd,
            "action": action,
        })
        return res

    def __call__(self, action, files=None, percentfunc=None, **kwargs):
        """Construct request, POST to server, json decode answer."""
        params = self._initparams(action, **kwargs)
        return json.loads(
            self._post(
                [],
                [("params", json.dumps(params))],
                files,
                percentfunc
            ).decode("UTF-8")
        )

    def send_backup(self, fname, fpath, percentfunc=None):
        """Backup a file on the server.

        @param fname: Relative file name on the server.
            Separated with / characters.
        @param fpath: Local path to the file.
        @percentfunct: When given, must have two parameters:
            percent_up,percent_down
        @return: Response from server.

        In the current implementation, response is a dict keyed by fname,
        and a non-empty value means an error message.
        """
        return self("backup", files=[(fname, fpath)], percentfunc=percentfunc)

    def recv_backup(self, fname, percentfunc=None):
        """Receive file data from server.

        @param fname: Relative file name on the server.
            Separated with / characters.
        @percentfunct: When given, must have two parameters:
            percent_up,percent_down
        @return: file contents as binary string.

        In the current implementation, response is a dict keyed by fname,
        and a non-empty value means an error message.
        """
        # raise Exception("TODO: restore to file instead of a binary string. MEMORY!!!!") # Uncomment to work but should fix instead.
        params = self._initparams("restore", fname=fname)
        return self._post(
            [], [("params", json.dumps(params))], [],
            percentfunc
        )

    def check_exists(self, fname):
        """Tell if a file or directory exist on the server with the given name.

        @param fname: Relative file name on the server.
            Separated with / characters.
        @return: True/False
        """
        return self("check_exists", fname=fname)

    def file_exists(self, fname):
        """Tell if a file exist on the server.

        @param fname: Relative file name on the server.
            Separated with / characters.
        @return: True/False
        
        This will always return False for directories!
        """
        return self("file_exists", fname=fname)

    def directory_exists(self, fname):
        """Tell if a directory exist on the server.

        @param fname: Relative file name on the server.
            Separated with / characters.
        @return: True/False
        
        This will always return False for regular files!
        """
        return self("directory_exists", fname=fname)

    def listdir(self, relpath):
        """List contents of a relative path on the server.
        
        @param relpath: A list of names.
        """
        return self("listdir", relpath=relpath)

    def utcnow(self):
        """Get UTC timestamp (ticks) from server."""
        return self("utcnow")

    # Administrative functions, requiring "A" permission.
    def getusers(self):
        """List users on the server."""
        return self("getusers")

    def saveuser(self, save_login, save_prefix, save_perms, save_password=None):
        """Save a user.
        
        If the user does not exist then it will be created.
        Keyword parameters are:
        
            login - identifies the user
            perfix - prefix for the user, a string separated by u"/"
            perms - permission string
            password - use None if it should not be changed.
        """
        return self("saveuser",
                    save_login=save_login,
                    save_prefix=save_prefix,
                    save_perms=save_perms,
                    save_password=save_password)

    def deleteuser(self, delete_login):
        """Delete a user."""
        return self("deleteuser", delete_login=delete_login)


class BlindFsListener(threading.Thread, FsListener):
    def is_stopping(self):
        return self.stop_requested.isSet()

    def __init__(self, client, sender, relpath, onchange):
        self.client = client
        self.sender = sender
        self.relpath = relpath
        self.onchange = onchange
        self.stop_requested = threading.Event()
        self.stopped = threading.Event()
        self.uid = None
        threading.Thread.__init__(self)
        FsListener.__init__(self)  # This will create a dummy uid but we will overwrite it later in run().

    def request_stop(self):
        """Request a stop on the listening thread."""
        self.stop_requested.set()

    def is_stopped(self):
        """Tells if the listening thread has stopped."""
        return self.stopped.is_set()

    def run(self):
        self.stopped.clear()
        self.stop_requested.clear()
        self.uid = self.client("listenchanges", root=self.relpath)
        while not self.stop_requested.is_set():
            changes = self.client("pollchanges", uid=self.uid)
            if changes:
                for eventPath, eventType, eventUid in changes:
                    self.onchange(self.sender, eventPath, eventType, eventUid)
        self.stopped.set()

    def get_uid(self):
        """Get unique identifier for the listener.

        This can be used to send notification messages that are not to be sent back to this listener."""
        return self.uid


class BlindFsProvider(FsProvider):
    """FsProvider that is provided by a backup server.

    @param client: A Client instance
    @param root: The root parameter must be a list of path elements.
        It represents the relative path on the server that will be
        snychronized.
    """

    def __init__(self, client, root, tmpdir):
        assert (isinstance(client, Client))
        assert (isinstance(root, list))
        if root and not root[0]:
            raise Exception("BlindFsProvider: root cannot be [''], it must be []. Hint: use :// instead of :///")
        self.client = client
        self.root = root
        self._iscasesensitive = None
        self.tmpdir = tmpdir
        FsProvider.__init__(self)

    def clone(self):
        res = BlindFsProvider(self.client, self.root, self.tmpdir)
        res.uid = self.get_uid()
        return res

    def drill(self, relpath):
        """Change root of the FsProvider to a new subdir.

        @param relpath: a list of path items

        Should only use it on a clone."""
        assert (isinstance(relpath, list))
        self.root = self.root + relpath

    def get_event_relpath(self, eventPath):
        """Convert the full path of an event into a path relative to this provider.

        @return: a list of path items"""
        myroot = "/".join(self.root)
        assert (eventPath.startswith(myroot))
        return eventPath[len(myroot) + 1:].split("/")

    @classmethod
    def _prefixed(cls, relpath, items):
        """Add prefix to items."""
        return [relpath + [item] for item in list(items)]

    def _remotepath(self, relpath):
        return self.root + relpath

    def iscasesensitive(self):
        if self._iscasesensitive is None:
            self._iscasesensitive = self.client("iscasesensitive")
        return self._iscasesensitive

    def listdir(self, relpath):
        # print("listdir",relpath,self._remotepath(relpath))
        return self.client("listdir", relpath=self._remotepath(relpath))

    def getinfo(self, items, encrypted):
        root = "/".join(self.root)
        # map object cannot be serialized, need to convert items to a list.
        return self.client(
            "getinfo", root=root, items=list(items), encrypted=encrypted)

    def sendchanges(self, delet, dcopy, fcopy):
        # Delete unwanted first
        for dpath in delet:
            yield (self.DELETE, "/".join(dpath))
        # Then create new directories
        infos = self.getinfo(dcopy, bool(self.decryptionkey))
        for idx, dpath in enumerate(dcopy):
            # use getinfo here, but need to have some buffering?
            atime, mtime, fsize = infos[idx]
            yield (
                self.DIRECTORY,
                "/".join(dpath),
                atime, mtime)
            subdnames, subfnames = self.listdir(dpath)
            for change in self.sendchanges(
                    [],
                    self._prefixed(dpath, subdnames),
                    self._prefixed(dpath, subfnames)):
                yield change
        # Finally send file data
        # TODO: make this much more efficient. Do not want to create one request per file, especially if files are small.
        infos = self.getinfo(fcopy, bool(self.decryptionkey))
        for idx, relpath in enumerate(fcopy):
            atime, mtime, fsize = infos[idx]
            file_data = self.client.recv_backup(
                "/".join(self._remotepath(relpath)))
            localpath = create_tmp_file_for(self.tmpdir)
            fout = open(localpath, "wb+")
            try:
                fout.write(file_data)
                fout.close()
                yield (
                    self.FILE, "/".join(relpath),
                    atime, mtime, fsize, localpath, self.RECEIVER)
            finally:
                if os.path.isfile(localpath):
                    os.unlink(localpath)

    def receivechanges(self, sender):
        # Unfortunately, we have to make our own schedule here.
        # Small files should be sent at once to minimize the number
        # of requests on the server.
        # TODO: store changes in a tmp file because there can be many.
        root = "/".join(self.root)
        delet, dcopy, fcopy = [], [], []
        files, encfiles = [], []
        ownedfiles = []
        cnt, totalsize = 0, 0
        try:
            while True:
                change = next(sender)
                op, *args = change
                if op == self.DELETE:
                    # (self.DELETE, converted_path)
                    change = (self.DELETE, "/".join(
                        self.recrypt_path_items(change[1].split("/")))
                              )
                    delet.append(change)
                    cnt += 1
                elif op == self.DIRECTORY:
                    # (self.DIRECTORY,converted_path,atime,mtime)
                    change = list(change)
                    change[1] = "/".join(self.recrypt_path_items(change[1].split("/")))
                    dcopy.append(tuple(change))
                    cnt += 1
                elif op == self.FILE:
                    # (self.FILE,converted_path,atime,mtime,fsize,fpath,owner)
                    selpath, atime, mtime, fsize, fpath, owner = args
                    selpath = "/".join(
                        self.recrypt_path_items(selpath.split("/")))
                    if owner == self.RECEIVER:
                        ownedfiles.append(fpath)
                    # Hide original full path from the server.
                    # The owner parameter is meaningless on the server side
                    # (server cannot own a file on the client side) so it is
                    # omited.
                    change = (self.FILE, selpath, atime, mtime, fsize, "")
                    fcopy.append(change)
                    cnt += 1
                    totalsize += args[3]
                    if self.encryptionkey and self.decryptionkey:
                        encpath = create_tmp_file_for(fpath)
                        cryptfile.recrypt_file(
                            cryptfile.hashkey(self.decryptionkey),
                            cryptfile.hashkey(self.encryptionkey),
                            fpath, encpath)
                        encfiles.append(encpath)
                        files.append([selpath, encpath])
                    elif self.encryptionkey:
                        encpath = create_tmp_file_for(fpath)
                        cryptfile.encrypt_file(
                            self.encryptionkey, fpath, encpath)
                        encfiles.append(encpath)
                        files.append([selpath, encpath])
                    elif self.decryptionkey:
                        encpath = create_tmp_file_for(fpath)
                        cryptfile.decrypt_file(
                            self.decryptionkey, fpath, encpath)
                        encfiles.append(encpath)
                        files.append([selpath, encpath])
                    else:
                        files.append([selpath, fpath])
                else:
                    raise Exception("Protocol error")
                if cnt > 1000 or totalsize > 1024 * 1024:
                    self.client(
                        "receivechanges",
                        root=root, uid=self.get_uid(),
                        delet=delet, dcopy=dcopy, fcopy=fcopy,
                        files=files
                    )
                    for encpath in encfiles:
                        os.unlink(encpath)
                    encfiles.clear()
                    for ownedpath in ownedfiles:
                        os.unlink(ownedpath)
                    ownedfiles.clear()
                    delet.clear()
                    dcopy.clear()
                    fcopy.clear()
                    files.clear()
        except StopIteration:
            pass
        if cnt:
            self.client(
                "receivechanges",
                root=root, uid=self.get_uid(),
                delet=delet, dcopy=dcopy, fcopy=fcopy,
                files=files
            )
            for encpath in encfiles:
                os.unlink(encpath)
            encfiles.clear()
            for ownedpath in ownedfiles:
                os.unlink(ownedpath)
            ownedfiles.clear()

    def listenchanges(self, onchange) -> FsListener:
        """Listen for changes in the filesystem."""
        # Note: listenchanges always uses relative paths on the sedrver.
        # So instead of self.root, we pass "" here!
        listener = BlindFsListener(self.client, self, "", onchange)
        listener.start()
        return listener
