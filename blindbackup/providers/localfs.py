#!/usr/bin/env python3
import os.path
import shutil
import threading
import time
import uuid

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .. import cryptfile
from ..util import *
from ..syncdir import FsProvider, FsListener, EInvalidPath


class LocalFsListener(threading.Thread, FileSystemEventHandler, FsListener):
    def __init__(self, sender, relpath, onchange):
        self.sender = sender
        self.relpath = relpath
        self.onchange = onchange
        self.stop_requested = threading.Event()
        self.stopped = threading.Event()
        threading.Thread.__init__(self)
        FileSystemEventHandler.__init__(self)
        FsListener.__init__(self)
        self.uid = str(uuid.uuid4())

    def is_stopping(self):
        return self.stop_requested.isSet()

    def _onchange(self, path, typ, uid):
        # if not self.sender.should_ignore_event(path):
        self.onchange(self.sender, path, typ, uid)

    def on_moved(self, event):
        FileSystemEventHandler.on_moved(self, event)
        src_relpath = os.path.abspath(event.src_path)
        dst_relpath = os.path.abspath(event.dest_path)
        self._onchange(src_relpath, FsProvider.DELETE, self.sender.get_uid())
        if os.path.isdir(event.dest_path):
            self._onchange(dst_relpath, FsProvider.DIRECTORY, self.sender.get_uid())
        else:
            self._onchange(dst_relpath, FsProvider.FILE, self.sender.get_uid())

    def on_created(self, event):
        FileSystemEventHandler.on_created(self, event)
        src_relpath = os.path.abspath(event.src_path)
        if os.path.isdir(event.src_path):
            self._onchange(src_relpath, FsProvider.DIRECTORY, self.sender.get_uid())
        else:
            self._onchange(src_relpath, FsProvider.FILE, self.sender.get_uid())

    def on_deleted(self, event):
        FileSystemEventHandler.on_deleted(self, event)
        src_relpath = os.path.abspath(event.src_path)
        self._onchange(src_relpath, FsProvider.DELETE, self.sender.get_uid())

    def on_modified(self, event):
        FileSystemEventHandler.on_modified(self, event)
        src_relpath = os.path.abspath(event.src_path)
        if os.path.isdir(event.src_path):
            self._onchange(src_relpath, FsProvider.DIRECTORY, self.sender.get_uid())
        else:
            self._onchange(src_relpath, FsProvider.FILE, self.sender.get_uid())

    def get_uid(self):
        """Get unique identifier for the listener.

        This can be used to send notification messages that are not to be sent back to this listener."""
        return self.uid

    def request_stop(self):
        """Request a stop on the listening thread."""
        self.stop_requested.set()

    def is_stopped(self):
        """Tells if the listening thread has stopped."""
        return self.stopped.is_set()

    def run(self):
        self.stopped.clear()
        self.stop_requested.clear()
        observer = Observer()
        observer.schedule(self, self.relpath, recursive=True)
        observer.start()
        try:
            while not self.stop_requested.is_set():
                time.sleep(1)
        finally:
            observer.stop()
        observer.join()
        self.stopped.set()


class LocalFsProvider(FsProvider):
    """This class represents a folder stored on a local filesystem.


    The LocalFsProvider subclass has a special attribute called
    file_data_in_change. When this is set to True, then the fpath
    parameter in receivechanges/FILE becomes a binary string containing
    file contents (instead of a file path). In this case the owner
    argument is ignored.

    """

    @classmethod
    def get_name(cls):
        return "localfs"

    def __init__(self, root, can_create: bool, settings: dict):
        """Local filesystem provider.

        @param root: A local path of a directory that will be the root
            for sync operations. Must be an existing directory.

        """
        if not os.path.isdir(root):
            if can_create:
                os.mkdir(root)
            else:
                raise ValueError("Not a directory: %s" % root)

        self.root = os.path.abspath(root)
        self.settings = settings
        # Set this flag to tell that file data in a change is not a file
        # path but the file data itself.
        self.file_data_in_change = False
        self._ignored = {}
        self.ignore_ttl = 1.0  # Ignore fs changes for items that has just been updated by the provider for this amount of time.
        super().__init__()

    def clone(self):
        res = LocalFsProvider(self.root, False, self.settings)
        res.uid = self.get_uid()
        return res

    def drill(self, relpath):
        """Change root of the FsProvider to a new subdir.

        Should only use it on a clone."""
        assert (isinstance(relpath, list))
        self.root = os.path.join(self.root, os.sep.join(relpath))

    def get_event_relpath(self, event_path):
        """Convert the full path of an event into a path relative to this provider.

        @return: a list of path items"""
        assert (event_path.startswith(self.root))
        return event_path[len(self.root) + len(os.sep):].split(os.sep)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.root))

    def get_localpath(self, relpath):
        """Convert platform independent relative path to local path.

        @param relpath: A list of path items.
        @return: system specific path with current root preprended."""
        if os.pardir in relpath or os.curdir in relpath or \
                (relpath and os.sep == relpath[0]):
            raise Exception("Got unsafe relative path: %s" % relpath)
        return os.path.join(self.root, *relpath)

    def remove(self, relpath):
        """Use this to remove by a relpath."""
        self._remove(self.get_localpath(relpath))

    def iscasesensitive(self):
        # TODO: is there a more general way to identify?
        return sys.platform != "win32"

    def listdir(self, relpath):
        localpath = self.get_localpath(relpath)
        if not os.path.isdir(localpath):
            raise EInvalidPath("Directory %s does not exist." % "/".join(relpath))
        names = os.listdir(localpath)
        dnames, fnames = [], []
        for name in names:
            if name not in [os.curdir, os.pardir]:
                fpath = os.path.join(localpath, name)
                if os.path.islink(fpath):
                    pass
                elif os.path.isdir(fpath):
                    dnames.append(name)
                elif os.path.isfile(fpath):
                    fnames.append(name)
        return dnames, fnames

    def getinfo(self, items, encrypted):
        infos = []
        for item in items:
            fpath = self.get_localpath(item)
            st = os.stat(fpath)
            if encrypted:
                fsize = cryptfile.get_origsize(fpath)
            else:
                fsize = st.st_size
            infos.append((st.st_atime, st.st_mtime, fsize))
        return infos

    def sendchanges(self, delet, dcopy, fcopy):
        # Delete unwanted first
        for dpath in delet:
            yield (self.DELETE, "/".join(dpath))
        # Then create new directories
        for dpath in dcopy:
            localpath = self.get_localpath(dpath)
            st = os.stat(localpath)
            yield (
                self.DIRECTORY,
                "/".join(dpath),
                st.st_atime, st.st_mtime)
            subdnames, subfnames = self.listdir(dpath)
            for change in self.sendchanges(
                    [],
                    self._prefixed(dpath, subdnames),
                    self._prefixed(dpath, subfnames)):
                yield change
        # Finally send file data
        for fpath in fcopy:
            localpath = self.get_localpath(fpath)
            st = os.stat(localpath)
            yield (
                self.FILE, "/".join(fpath), st.st_atime,
                st.st_mtime, st.st_size, localpath, self.SENDER)

    # def _ignore_events(self,fpath):
    #     relpath = tuple(self.get_event_relpath(fpath))
    #     self._ignored[relpath] = None
    #
    # def _resume_events(self,fpath):
    #     relpath = tuple(self.get_event_relpath(fpath))
    #     self._ignored[relpath] = time.time() + self.ignore_ttl
    #
    # def should_ignore_event(self, fpath):
    #     relpath = tuple(self.get_event_relpath(fpath))
    #     if relpath in self._ignored:
    #         expired = self._ignored[relpath] < time.time()
    #         if expired:
    #             del self._ignored[relpath]
    #             return True
    #         else:
    #             return False
    #     else:
    #         return False

    def _remove(self, localpath):
        # self._ignore_events(localpath)
        # try:
        if os.path.isfile(localpath):
            os.unlink(localpath)
        elif os.path.isdir(localpath):
            shutil.rmtree(localpath)

    # finally:
    #    self._resume_events(localpath)

    def receivechanges(self, sender):
        try:
            while True:
                change = next(sender)
                op, *args = change
                if op == self.DELETE:
                    relpath = self.recrypt_path_items(args[0].split("/"))
                    localpath = self.get_localpath(relpath)
                    self._remove(localpath)
                elif op == self.DIRECTORY:
                    selpath, atime, mtime = args
                    relpath = self.recrypt_path_items(selpath.split("/"))
                    localpath = self.get_localpath(relpath)
                    self._remove(localpath)
                    # self._ignore_events(localpath)
                    # try:
                    os.mkdir(localpath)
                    os.utime(localpath, (atime, mtime))
                    # finally:
                    #    self._resume_events(localpath)
                elif op == self.FILE:
                    selpath, atime, mtime, fsize, fsource, owner = args
                    delete_orig = owner == self.RECEIVER
                    try:
                        relpath = self.recrypt_path_items(selpath.split("/"))
                        dstpath = self.get_localpath(relpath)
                        # self._ignore_events(dstpath)
                        # self._ignore_events(dstpath+".~ftmp")
                        # self._ignore_events(dstpath+".~tmp")
                        # try:
                        if self.file_data_in_change:
                            with (open(dstpath + ".~ftmp", "wb+")) as fout:
                                fout.write(fsource)
                            fsource = dstpath + ".~ftmp"
                            owner = self.RECEIVER
                            delete_orig = True
                        # TODO: implement progressfunc here? Maybe.
                        if self.encryptionkey and self.decryptionkey:
                            cryptfile.recrypt_file(
                                cryptfile.hashkey(self.decryptionkey),
                                cryptfile.hashkey(self.encryptionkey),
                                fsource,
                                dstpath + ".~tmp"
                            )
                        elif self.encryptionkey:
                            cryptfile.encrypt_file(
                                self.encryptionkey,
                                fsource,
                                dstpath + ".~tmp"
                            )
                        elif self.decryptionkey:
                            cryptfile.decrypt_file(
                                self.decryptionkey,
                                fsource,
                                dstpath + ".~tmp"
                            )
                        else:
                            if owner == self.RECEIVER:
                                # print("!!!! DOH SAVED A COPY !!!!")
                                os.rename(fsource, dstpath + ".~tmp")
                                delete_orig = False
                            else:
                                shutil.copyfile(fsource, dstpath + ".~tmp")
                        self._remove(dstpath)
                        os.rename(dstpath + ".~tmp", dstpath)
                        os.utime(dstpath, (atime, mtime))
                        # finally:
                        #    self._resume_events(dstpath+".~tmp")
                        #    self._resume_events(dstpath+".~ftmp")
                        #    self._resume_events(dstpath)
                    finally:
                        if delete_orig:
                            os.unlink(fsource)
                else:
                    raise Exception("Protocol error")
        except StopIteration:
            pass

    def listenchanges(self, onchange) -> FsListener:
        """Listen for changes in the filesystem."""
        listener = LocalFsListener(self, self.root, onchange)
        listener.start()
        return listener
