import os
from typing import List, Tuple, Dict, Sequence

import requests
import time
from dateutil.parser import parse as parse_ts

from ..syncdir import FsProvider
from ..util import create_tmp_file_for

TIMEOUT = 100.0
DEBUG = True


class FolderInfo:
    def __init__(self, folder_id, title, updated):
        self.folder_id = folder_id
        self.title = title
        self.updated = updated

    def getinfo(self):
        return (self.updated, self.updated, 0)


class FileInfo:
    def __init__(self, file_id, title, updated, size, view_url):
        self.file_id = file_id
        self.title = title
        self.updated = updated
        self.size = size
        self.view_url = view_url

    def getinfo(self):
        return (self.updated, self.updated, self.size)


class OnlyOfficeProvider(FsProvider):
    """This class represents a folder stored in OnlyOffice.

    Uses the API published at https://api.onlyoffice.com/portals/basic

    Settings:

        server_url - base URL for the server e.g. "https://some_server.com"
        login - your login name e.g. "jack"
        password - your password
        root_folder_id - identifier of the root folder (e.g. your folder OR common files folder)

    """

    @classmethod
    def get_name(cls):
        return "onlyoffice"

    def __init__(self, path: str, can_create: bool, settings: dict, _token_holder=None, root=None):
        if root is None:
            if path:
                root = path.split("/")
            else:
                root = []
        if root and not root[0]:
            raise Exception("OnlyOfficeProvider: root cannot be [''], it must be []. Hint: use :// instead of :///")

        if can_create:
            raise Exception("OnlyOfficeProvider cannot write to OnlyOffice.")

        self.root = root
        self.settings = settings
        self._token_holder = _token_holder or {}
        self.root_folder_id = settings["root_folder_id"]
        self.tmp_dir = settings.get("tmp_dir", None)

        # TODO: save these into a database!
        self._folder_infos: Dict[Tuple[str], FolderInfo] = {(): FolderInfo(self.root_folder_id, "", 0)}
        self._file_infos: Dict[Tuple[str], FileInfo] = {}
        self._folder_folders: Dict[str, List[FolderInfo]] = {}
        self._folder_files: Dict[str, List[FileInfo]] = {}
        super().__init__()

    def clone(self):
        res = OnlyOfficeProvider(None, False, self.settings, root=self.root)
        res.uid = self.get_uid()
        # Make sure they share the same cache
        res._folder_infos = self._folder_infos
        res._file_infos = self._file_infos
        res._folder_folders = self._folder_folders
        res._folder_files = self._folder_files

        return res

    def drill(self, relpath):
        """Change root of the FsProvider to a new subdir.

        Should only use it on a clone."""
        assert (isinstance(relpath, list))
        self.root = os.path.join(self.root, os.sep.join(relpath))

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.root))

    def iscasesensitive(self):
        return False

    def _create_headers(self, no_auth=False):
        if no_auth:
            return {"Accept": "application/json"}
        else:
            return {"Accept": "application/json", "Authorization": self._token_holder["token"]}

    def _post(self, relpath, data: dict, no_auth=False):
        url = self.settings["server_url"] + "/api/2.0/" + relpath
        response = requests.post(url, data=data, headers=self._create_headers(no_auth), timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _get(self, relpath, no_auth=False):
        url = self.settings["server_url"] + "/api/2.0/" + relpath
        response = requests.get(url, headers=self._create_headers(no_auth), timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def _authenticate(self):
        if not self._token_holder or self._token_holder["expires"] < time.time():
            result = self._post("authentication.json", dict(
                username=self.settings["login"],
                password=self.settings["password"],
            ), no_auth=True)
            response = result["response"]
            token = response["token"]
            expires = parse_ts(response["expires"]).timestamp() - 100
            self._token_holder.update(dict(token=token, expires=expires))

    def _norm_path(self, path: Sequence[str]) -> Tuple[str]:
        """Normalize path"""
        return tuple([item.strip().lower() for item in path])

    def _cache_folder_info(self, norm_path: Tuple[str]):
        self._authenticate()
        if norm_path not in self._folder_folders:
            if norm_path:
                parent_path = norm_path[:-1]
                self._cache_folder_info(parent_path)
                folder_id = self._folder_infos[norm_path].folder_id
            else:
                folder_id = self.root_folder_id

            info = self._get("files/%s" % folder_id)

            folders = info["response"]["folders"]
            folder_infos = []
            for folder in folders:
                folder_id = folder["id"]
                title = folder["title"]
                updated = parse_ts(folder["updated"]).timestamp()
                if title != "...":
                    path = (*norm_path, title.strip().lower())
                    folder_info = FolderInfo(folder_id, title, updated)
                    self._folder_infos[path] = folder_info
                    folder_infos.append(folder_info)
            self._folder_folders[norm_path] = sorted(folder_infos, key=lambda fi: fi.title)

            files = info["response"]["files"]
            file_infos = []
            for file in files:
                file_id = file["id"]
                title = file["title"]
                updated = parse_ts(file["updated"]).timestamp()
                size = int(file["pureContentLength"])
                view_url = file["viewUrl"]
                path = (*norm_path, title.strip().lower())
                file_info = FileInfo(file_id, title, updated, size, view_url)
                self._file_infos[path] = file_info
                file_infos.append(file_info)
            self._folder_files[norm_path] = sorted(_file_infos, key=lambda fi: fi.title)

        if norm_path not in self._folder_infos:
            raise KeyError("No such folder: %s" % "/".join(norm_path))

    def listdir(self, relpath: Sequence[str]):
        """List items for a given relative path.


        @param path: a sequence containing path elements. This
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
        if DEBUG:
            print("LIST", relpath)
        norm_path = self._norm_path(self.root + relpath)
        self._cache_folder_info(norm_path)
        dnames = [folder_info.title for folder_info in self._folder_folders[norm_path]]
        fnames = [file_info.title for file_info in self._folder_files[norm_path]]
        return (dnames, fnames)

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
        self._authenticate()
        if encrypted:
            raise NotImplementedError("Encryption is not implemented in OnlyOfficeProvider")
        result = []
        for relpath in items:
            norm_path = self._norm_path(self.root + relpath)
            if norm_path[:-1] not in self._folder_infos:
                self._cache_folder_info(norm_path[:-1])

            if norm_path in self._folder_infos:
                result.append(self._folder_infos[norm_path].getinfo())
            elif norm_path in self._file_infos:
                result.append(self._file_infos[norm_path].getinfo())
            else:
                raise KeyError("No such item: %s" % relpath)
        return result

    @classmethod
    def _prefixed(cls, relpath, items):
        """Add prefix to items."""
        return [relpath + [item] for item in list(items)]

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
            norm_path = self._norm_path(self.root + relpath)
            file_info = self._file_infos[norm_path]
            atime, mtime, fsize = infos[idx]
            localpath = create_tmp_file_for(self.tmp_dir)
            fout = open(localpath, "wb+")
            try:
                with requests.get(file_info.view_url, stream=True, headers=self._create_headers(),
                                  timeout=TIMEOUT) as r:
                    r.raise_for_status()
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:  # filter out keep-alive new chunks
                            fout.write(chunk)
                fout.close()
                yield (
                    self.FILE, "/".join(relpath),
                    atime, mtime, fsize, localpath, self.RECEIVER)
            finally:
                if os.path.isfile(localpath):
                    os.unlink(localpath)
