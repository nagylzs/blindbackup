#!/usr/bin/env python3
import os.path
import threading

from .. import cryptfile
from ..util import *
from ..syncdir import FsProvider, FsListener


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

    @classmethod
    def get_name(cls):
        return "blindfs"

    def __init__(self, client: "Client", root, tmp_dir):
        assert (isinstance(root, list))
        if root and not root[0]:
            raise Exception("BlindFsProvider: root cannot be [''], it must be []. Hint: use :// instead of :///")
        self.client = client
        self.root = root
        self._iscasesensitive = None
        self.tmpdir = tmp_dir
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
