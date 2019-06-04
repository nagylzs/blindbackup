#!/usr/bin/env python3
import copy
import functools
import uuid

from blindbackup import cryptfile


class EInvalidPath(Exception):
    pass


class FsListener(object):
    """Filesystem listener objects should implement these methods."""

    def request_stop(self):
        """Request a stop on the listening thread."""
        raise NotImplementedError

    def is_stopping(self):
        """Tells if stop was requested on the listening thread."""
        raise NotImplementedError

    def is_stopped(self):
        """Tells if the listening thread has stopped."""
        raise NotImplementedError

    def join(self):
        """Wait until the listening thread has stopped."""
        raise NotImplementedError


# TODO: add support for synchronizing symbolic links.
class FsProvider:
    """General file system provider.

    Implementing these methods for any storage media will allow you
    to synchronize files with any other FSProvier.

    About encryption:

        * Encryption/decryption always happens in the receiver object:
          the received gets the full file path and encrypts/decrypts
          file data to the destination.

        * Receiver side can of course also encrypt and decrypt file
            names and directory names.

        * By specifying both encryptionkey and decryptionkey you can
            re-crypt files between locations.

        * If you implement a custom FsProvider that transfers data over
          the network, then you should (probably) create a client
          FsProvider that encrypts data in receivechanges() method
          BEFORE sending it out on the network.
    """
    DIRECTORY = 1
    FILE = 2
    DELETE = 3

    SENDER = 0
    RECEIVER = 1

    encryptionkey = None
    decryptionkey = None

    def __init__(self):
        self.uid = str(uuid.uuid4())  # Create unique identifier for this FsProvider

    @classmethod
    def get_name(cls):
        """Name of the FsProvider."""
        raise NotImplementedError

    def get_uid(self):
        """Get unique identifier for the FsProvider.

        This can be used to identify the origin of filesystem notification messages."""
        return self.uid

    def iscasesensitive(self):
        """Tell if the provided filesystem is case sensitive or not."""
        raise NotImplementedError

    @classmethod
    def decrypt_path_items(cls, key, items):
        """Decrypts a relative path."""
        if key:
            return list(map(functools.partial(
                cryptfile.decrypt_filename, key), items))
        else:
            return items

    @classmethod
    def encrypt_path_items(cls, key, items):
        """Encrypts a relative path."""
        if key:
            return list(map(functools.partial(
                cryptfile.encrypt_filename, key), items))
        else:
            return items

    def recrypt_path_items(self, items):
        if self.encryptionkey and self.decryptionkey:
            return self.encrypt_path_items(
                self.encryptionkey,
                self.decrypt_path_items(self.decryptionkey, items))
        elif self.decryptionkey:
            return self.decrypt_path_items(
                self.decryptionkey, items)
        elif self.encryptionkey:
            return self.encrypt_path_items(
                self.encryptionkey, items)
        else:
            return items

    def clone(self):
        """Cretate clone.

        This creates another FsProvider instance that has the same uid.
        You can use set_root() to change its root later."""
        raise NotImplementedError

    def drill(self, relpath):
        """Change root of the FsProvider.

        @param relpath: a list of path items

        Should only use it on a clone."""
        raise NotImplementedError

    def get_event_relpath(self, eventPath):
        """Convert the full path of an event into a path relative to this provider.

        @return: a list of path items"""
        raise NotImplementedError

    def listdir(self, relpath):
        """List items for a given relative path.

        @param relpath: a sequence containing path elements. This
            deterimines the relative path of the directory.
        @return: a tuple of (dnames,fnames) where dnames should be
            a sequence of directory names, and fnames should be a
            sequence of file names. You MUST NOT put os.curdir ('.') or
            os.pardir ('..') into these elements. You MUST NOT return
            any name that belongs to a symbolic link, only directories
            and files.

        This method should never encrypt or decrypt filenames, and its
        relpath argument will also be a raw value e.g. something that
        does not need to be encrypted/decrypted before listing contents.

        """
        raise NotImplementedError

    def getinfo(self, items, encrypted):
        """Get file information on a list of items.

        @param items: a sequence of relative paths that should be
            examined.
        @param encrypted: True/False value. True value indicates that
            files are in encrypted state, so the physical file size
            is not relevant. Need determine and return the original
            file size.
        @return: a list of information tuples. Each tuple should contain
            two values: ( accesstime, modificationtime, filesize ).

        This might also be called for directories, in which case the
        filesize element has no meaning and can be zero.
        """
        raise NotImplementedError

    def sendchanges(self, delet, dcopy, fcopy):
        """Send changes.

        This should be a generator that yields commands that can
        be received and interpreted by a DirSource receiver.

        @param delet: A sequence of files/directories to be delete.
        @param dcopy: A sequence of directories to by copied.
            This is recursive (e.g. copy everything).
        @param fcopy: A sequence of files to copied.

        When sending deletion, this method should yield this tuple:

            (self.DELETE, converted_path)

            where converted_path value:

            * must be a normal (non-binary) string
            * contain path elements must be separated by "/" characters
                even if your local OS uses different separator.

        When sending directories, this method should yield this tuple:

            (self.DIRECTORY,converted_path,atime,mtime)

            where the atime and mtime values must be creation and
            modification time value as returned by os.stat.

        Please note that dcopy means sending directory creation,
        and all directories and files inside. So whenever you
        send a directory, you must also send its contents.

        When sending files, this method should yield this tuple:

            (self.FILE,converted_path,atime,mtime,fsize,fpath,owner)

            where fsize is the size of the file in bytes and fpath is
            a platform-dependent full file path.

            The owner value should be a boolean value telling
            that the file is owned by the receiver or the sender.
            Defined as FsProvider.RECEIVER or FsProvider.SENDER.
            Sender owned files are immutable. The sender nor the receiver
            should delete or modify these files in any way. The sender
            is required to keep these files in the same state during the
            whole synchronization process. If the receiver wants to copy
            a sender owned file then its contents must actually be
            copied. Receiver owned files are temporary files created by
            the sender. They have been created for the receiver and they
            can be moved to their final destination by the receiver,
            or copied or whatever the receiver wishes to do with it.
            However, once they have fulfilled their purpose, the
            receiver is responsibe for freeing them up (e.g.
            unlink/delete from disk).

            Please note than in your implementation, when the owner is
            the receiver then there can still be an error on the receiver
            side. So if your yield returns with an exception, then the
            receiver will be stopped permanently and then you should
            try to delete the temporary file (if exists).

            When encryptionkey is given, source file must be encrypted
            and fpath of the encrypted file must be yielded.

            When decryptionkey is given, source file must be decrypted
            and fpath of the encrypted file must be yielded.

        The LocalFsProvider subclass has a special attribute called
        file_data_in_change. When this is set to True, then the fpath
        parameter becomes a binary string containing file contents
        (instead of a file path). In this case the owner argument is
        ignored.

        """
        raise NotImplementedError

    def receivechanges(self, sender):
        """Receive changes sent by a sender.

        @param sender: An iterator containing changes, as sent by
            sendchanges.


        For file data:

            When decryptionkey is given, source file data must be
            decrypted. When encryptionkey is given, source file must be
            decrypted before data is store.

        For details, see the sendchanges method."""
        pass

    def logchanges(self, sender):
        """A special chainfilter that logs changes to stdout."""
        for item in sender:
            logname = "/".join(self.decrypt_path_items(
                self.decryptionkey, item[1].split("/")))
            if item[0] == self.FILE:
                print("+", logname)
            elif item[0] == self.DIRECTORY:
                print("+", logname + "/")
            elif item[0] == self.DELETE:
                print("-", logname)
            yield item

    def listenchanges(self, onchange) -> FsListener:
        """Listen for changes in the filesystem.

        @param onchange: a bound method that will be called with these
            parameters: (sender, eventPath, eventType)

                sender - the FsProvider that has generated the event
                eventPath - relative path corresponding to the event
                eventType - type of the event, it can be:

                    FsProvider.FILE
                    FsProvider.DIRECTORY
                    FsProvider.DELETE

                eventUid - the unique identifier of the client that has sent the event
                    originally.

        @return: a threading object that implements FsListener methods.

        Descendants should implement this method and start a background thread.

        IMPLEMENTATION NOTE: listeners should automatically filter out changes that are caused by the
        listened fsprovider itself.

        """
        raise NotImplementedError


class SyncDir:
    CMP_IGNORE = 0
    CMP_CHANGED = 1
    CMP_NEWER = 2
    CMP_BIGGER = 3

    def _checkoptions(self, options):
        if options is None:
            res = {}
        else:
            res = copy.copy(options)
        res["syncdelete"] = res.get("syncdelete", False)
        res["mtcompare"] = res.get("mtcompare", self.CMP_CHANGED)
        res["sizecompare"] = res.get("sizecompare", self.CMP_CHANGED)

        if res["mtcompare"] not in [
            self.CMP_CHANGED, self.CMP_NEWER, self.CMP_IGNORE]:
            raise Exception("Invalid value for mtcompare option.")

        if res["sizecompare"] not in [
            self.CMP_CHANGED, self.CMP_BIGGER, self.CMP_IGNORE]:
            raise Exception("Invalid value for sizecompare option.")

        if (res["sizecompare"] == self.CMP_IGNORE) and \
                (res["mtcompare"] == self.CMP_IGNORE):
            raise Exception("Invalid sizecompare + mtcompare")

        return res

    # TODO: add option for case insensivity/sensitivity
    # TODO: add option to do symmetric compare. There is no point in
    # calling compare() twice for symmetric synchronization.
    def compare(self, src, dst, options=None, srckey=None, dstkey=None):
        """Use this method to compare two sources assymetricaly.

        @param src: something that implements LocalFsSource protocol.
        @param dst: something that implements LocalFsSource protocol.
        @param options: A dict containing these values:

            syncdelete: True/False. Set flag to sync deletions.
                        Default is False.
            mtcompare:  Determines comparison on last modification.
                        Possible values:

                            CMP_CHANGED - copy if modification time differs
                                This is the default.
                            CMP_NEWER   - copy if source was modified later
                            CMP_IGNORE  - do not use mtime for comparison

            sizecompare:Determines comparison on file size.
                        Possible values:

                            CMP_CHANGED - copy if size differs
                                This is the default.
                            CMP_BIGGER  - copy if source is bigger
                            CMP_IGNORE  - do not use size for comparison

            Specifying mtcompare=IGNORE and sizecompare=IGNORE is an
            error. If you specify both CMP_NEWER and CMP_BIGGER, then
            CMP_NEWER takes precedence. E.g. if the source file got
            smaller but newer, then it will be copied.
        
        @param srckey: Encryption key of src as returned by
            cryptfile.hashkey
        @param dstkey: Encryption key of dst as returned by
            cryptfile.hashkey
        """
        delet = []  # Deletions to be sent
        dcopy = []  # Directories to be copied
        fcopy = []  # Files to be copied

        options = self._checkoptions(options)
        fnop = lambda a: a
        keyopt = {'srckey': srckey, 'dstkey': dstkey,
                  'se': fnop, 'sd': fnop, 'de': fnop, 'dd': fnop}
        if srckey:
            keyopt['se'] = functools.partial(src.encrypt_path_items, srckey)
            keyopt['sd'] = functools.partial(src.decrypt_path_items, srckey)
        if dstkey:
            keyopt['de'] = functools.partial(dst.encrypt_path_items, dstkey)
            keyopt['dd'] = functools.partial(dst.decrypt_path_items, dstkey)

        self._docompare(src, dst, delet, dcopy, fcopy, [], options,
                        keyopt)
        return delet, dcopy, fcopy

    def sync(self, src, dst, options, srckey=None, dstkey=None, chainfilter=None):
        """Perform actions returned by sync().

        @param src: FsProvider, source to be synced from
        @param dst: FsProvider, destination to be synced to
        @param options: See the compare method.
        @param srckey: Encryption key for src, as returned by
            cryptfile.hashkey
        @param dstkey: Encryption key for dst, as returned by
            cryptfile.hashkey
        @param chainfilter: When given, it should be a generator that
            chains changes. This can also be used to filter out
            unwanted changes. However, please note that incorrect
            filtering may cause unexpected errors. (For example, if
            you exclude a directory, but don't exclude a file inside
            that directory, then copying file data may fail.) Example
            implementation is FsProvider.logchanges
        """
        delet, dcopy, fcopy = self.compare(src, dst, options, srckey, dstkey)
        delet = list(map(functools.partial(src.encrypt_path_items, srckey), delet))
        dcopy = list(map(functools.partial(src.encrypt_path_items, srckey), dcopy))
        fcopy = list(map(functools.partial(src.encrypt_path_items, srckey), fcopy))
        src.decryptionkey = None
        src.encryptionkey = None
        dst.decryptionkey = srckey
        dst.encryptionkey = dstkey
        if chainfilter:
            dst.receivechanges(chainfilter(src.sendchanges(
                delet, dcopy, fcopy)))
        else:
            dst.receivechanges(src.sendchanges(delet, dcopy, fcopy))

    @classmethod
    def _prefixed(cls, relpath, items):
        """Add prefix to items."""
        return [relpath + [item] for item in list(items)]

    def _info_compare(self, srcinfo, dstinfo, options):
        """Compare file information with the given options.

        @param srcinfo: A tuple of (atime,mtime,fsize) for source file.
        @param dstinfo: A tuple of (atime,mtime,fsize) for destination file.
        @param options: See the compare method.
        @return: True if the source file should be copied, False otherwise.

        """
        if options["mtcompare"] == self.CMP_NEWER:
            if srcinfo[1] - dstinfo[1] > 1.0:
                # print("_info_compare", srcinfo, dstinfo, "True #1")
                return True
        elif options["mtcompare"] == self.CMP_CHANGED:
            if abs(srcinfo[1] - dstinfo[1]) > 1.0:
                # print("_info_compare", srcinfo, dstinfo, "True #2")
                return True

        if options["sizecompare"] == self.CMP_BIGGER:
            if srcinfo[2] > dstinfo[2]:
                # print("_info_compare", srcinfo, dstinfo, "True #3")
                return True
        elif options["sizecompare"] == self.CMP_CHANGED:
            if srcinfo[2] != dstinfo[2]:
                # print("_info_compare", srcinfo, dstinfo, "True #4")
                return True

        # print("_info_compare", srcinfo, dstinfo, "False")
        return False

    def _docompare(self, src, dst, delet, dcopy, fcopy, relpath, options,
                   keyopt):
        # Get basic information for this relative path
        # print("=========_docompare %s ========="%relpath)
        # print("relpath",repr(relpath))

        src_dnames, src_fnames = src.listdir(keyopt['se'](relpath))
        dst_dnames, dst_fnames = dst.listdir(keyopt['de'](relpath))

        src_dnames = set(keyopt['sd'](src_dnames))
        src_fnames = set(keyopt['sd'](src_fnames))
        dst_dnames = set(keyopt['dd'](dst_dnames))
        dst_fnames = set(keyopt['dd'](dst_fnames))

        # Delete unwanted files
        if options["syncdelete"]:
            srcitems = src_fnames.union(src_dnames)
            dstitems = dst_fnames.union(dst_dnames)
            delet += self._prefixed(relpath, dstitems - srcitems)

        # Copy trees for new dirs.
        dcopy += self._prefixed(relpath, src_dnames - dst_dnames)
        # Copy new files
        fcopy += self._prefixed(relpath, src_fnames - dst_fnames)
        # Get extra information for conditional file data copy.
        items = self._prefixed(relpath, src_fnames.intersection(dst_fnames))
        src_infos = src.getinfo(list(map(keyopt['se'], items)), bool(keyopt['srckey']))
        dst_infos = dst.getinfo(list(map(keyopt['de'], items)), bool(keyopt['dstkey']))
        for idx, item in enumerate(items):
            # print(item, src_infos[idx], dst_infos[idx], options)
            if self._info_compare(src_infos[idx], dst_infos[idx], options):
                # print("fcopy+", item)
                fcopy.append(item)
        # Synchronize subdirectories recursively.
        for dname in src_dnames.intersection(dst_dnames):
            self._docompare(
                src, dst, delet, dcopy, fcopy,
                relpath + [dname], options, keyopt)


# Example usage:
if __name__ == "__main__":
    sd = SyncDir()
    src = LocalFsProvider("C:/Temp/src")
    dst = LocalFsProvider("C:/Temp/dst")
    sd.sync(src, dst, {
        "syncdelete": True,
        "mtcompare": sd.CMP_IGNORE,
        # "sizecompare": sd.CMP_IGNORE,
    })
