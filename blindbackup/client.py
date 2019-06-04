#!/usr/bin/env python3
import copy
import io
import json
import os.path
import pycurl
import urllib.parse

from blindbackup.util import localpath


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
        curl.setopt(pycurl.USERAGENT, "BlindBackup v2.0")
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
