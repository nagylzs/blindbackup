#!/usr/bin/env python3
import argparse
import atexit
import datetime
import functools
import json
import os
import os.path
import re
import shutil
import sys
import time
import traceback
import uuid

import psutil
import tornado.httpserver
import tornado.ioloop
import tornado.web

from blindbackup import util
from tornadostreamform.multipart_streamer import MultiPartStreamer
from blindbackup.syncdir import LocalFsProvider, EInvalidPath
from blindbackup.util import localpath

VALID_PERMCODES = u"WDRSTAN"
MAX_FILE_SIZE_DEFAULT = 10 * 1024 ** 4  # 10 TB


class AbortRequest(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg


def _checksafepath(fname):
    """Check if the given path is safe.

    @param fname: relative path
        If can either be a string separated with / chars, or a
        list of path items.

    Path may not contain '..','?','*' and cannot begin with / or .

    This method will raise an AbortRequest if something is wrong
    with the path. This method returns the localized version of the
    relative path that is a string with elements separated by os.sep.
    """
    if isinstance(fname, list):
        fname = "/".join(fname)
    fname = fname.replace("/", os.sep).replace("..", os.pardir)
    if (os.pardir in fname) or \
            '..' in fname or \
            '?' in fname or \
            '*' in fname or \
            fname.startswith(os.sep) or \
            fname.startswith(os.curdir + os.sep):
        raise AbortRequest(400, "Invalid filename.")
    return fname


class SecurityManager(object):
    """Manages a list of users.
    
    Can only be used from a single thread (async server).
    
    DO NOT USE FROM MULTIPLE THREADS OR PROCESSES.
    
    You can write into the passwd file on the disk, and
    it will be reloaded within the number of seconds defined in the
    TTL value below.
    
    Otherwise all updates should be done through a security manager 
    object, with this pattern:
    
    secmanager.beginupdate()
    # create/update users and groups here...
    secmanager.endupdate()
    
    """
    TTL = 1.0  # In seconds

    def __init__(self, config):
        self.config = config
        self._last_loaded = 0
        self._last_mtime = 0
        self._users = None

    def get_users(self) -> dict:
        self._load_all()
        return self._users

    def get_user(self, login):
        users = self.get_users()
        if login in users:
            return users[login]
        else:
            return None

    def _load_all(self):
        now = time.time()
        if self._last_loaded + self.TTL < now:
            mtime = os.stat(self.config["passwdfile"]).st_mtime
            if mtime != self._last_mtime:
                self._load_users()
                self._last_mtime = mtime
                self._last_loaded = now

    def _load_users(self):
        # TODO: check permissions of the passwd file and issue a warning when not protected.
        fpath = self.config["passwdfile"]
        print("Reloading users from %s" % fpath)
        self._users = {}
        self._passwords = {}
        lineno = 0
        for line in open(fpath, "r"):
            lineno += 1
            line = line.strip()
            if line and not line.startswith("#"):
                login, prefix, perms, *parts = line.split(":")
                pwd = ":".join(parts)
                login = login.strip().lower()
                prefix = prefix.strip()
                login_ok = re.match("[a-z][a-z0-9]*", login)
                prefix_ok = not prefix or re.match(
                    "[a-z][a-z0-9]*(/[a-z][a-z0-9]*)*", prefix) and \
                            not prefix.endswith("/")
                if not login_ok:
                    print("WARNING: invalid login name '%s' at line %d" % (login, lineno))
                if not prefix_ok:
                    print("WARNING: invalid prefix name '%s' at line %d" % (prefix, lineno))
                if login_ok and prefix_ok:
                    self._users[login] = {
                        "name": login,
                        "prefix": prefix,
                        "perms": perms,
                    }
                    self._passwords[login] = pwd

    def _dump_users(self):
        fpath = self.config["passwdfile"]
        print("Saving users to %s" % fpath)
        usernames = sorted(self._users.keys())
        with open(fpath + ".part", "w+") as fout:
            for username in usernames:
                user = self._users[username]
                # print("???",self._passwords)
                # print("???",self._passwords[username])
                line = "%s:%s:%s:%s" % (
                    username,
                    user["prefix"],
                    user["perms"],
                    self._passwords[username]
                )
                # print(repr(line))
                fout.write(line + "\n")
        bakfile = fpath + ".bak"
        if os.path.isfile(bakfile):
            os.unlink(bakfile)
        os.rename(fpath, bakfile)
        os.rename(fout.name, fpath)

    def check_password(self, login, password):
        user = self.get_user(login)
        if user:
            if not self._passwords[login]:
                return False  # Null password -> disable usedr
            else:
                return self._passwords[login] == password
        else:
            return False

    def get_perms(self, login):
        users = self.get_users()
        if login in users:
            return users[login]["perms"]
        else:
            return ""

    def save_user(self, params, currentlogin):
        # Make sure that we have a fresh db
        self.get_users()
        # Extract parameters
        login = params.get(u"save_login", u"")
        prefix = params[u"save_prefix"]
        _perms = params[u"save_perms"]
        password = params.get(u"save_password", None)

        # Validate parameters
        login = login.strip().lower()
        prefix = prefix.strip()
        login_ok = re.match("[a-z][a-z0-9]*", login)
        prefix_ok = not prefix or re.match(
            "[a-z][a-z0-9]*(/[a-z][a-z0-9]*)*", prefix) and \
                    not prefix.endswith("/")
        if not login_ok:
            raise AbortRequest(400, "Invalid login name '%s'" % login)
        if not prefix_ok:
            raise AbortRequest(400, "Invalid prefix '%s'" % prefix)
        if login == currentlogin:
            raise AbortRequest(400, "You should not change yourself.")
        perms = u""
        for permcode in VALID_PERMCODES:
            if permcode in _perms:
                perms += permcode
        if not password:
            if login in self._passwords:
                password = self._passwords[login]

        # TODO: check password policy here?
        if not password:
            password = u""
        elif password and len(password) < 6:
            raise AbortRequest(403, "Minimum password length is 6.")
        elif password == login:
            raise AbortRequest(403, "Password and login must not match.")

        if login_ok and prefix_ok:
            # Save to memory
            user = {
                "name": login,
                "prefix": prefix,
                "perms": perms,
            }
            print("Saving user %s" % login)
            self._users[login] = user
            self._passwords[login] = password
            self._dump_users()

    def delete_user(self, params, currentlogin):
        # Make sure that we have a fresh db
        self.get_users()
        # Extract parameters
        login = params.get(u"delete_login", u"")

        # Validate parameters
        login = login.strip().lower()
        login_ok = re.match("[a-z][a-z0-9]*", login)
        if not login_ok:
            raise AbortRequest(400, "Invalid login name '%s'" % login)

        if login == currentlogin:
            raise AbortRequest(400, "You should not delete yourself.")

        if login in self._users:
            print("Deleting user %s" % login)
            del self._users[login]
            self._dump_users()
        else:
            raise AbortRequest(404, "Cannot delete, user does not exist.")


class EventListener(object):
    """Listen changes in the file system, and distribute notification events to listeners."""

    def __init__(self, config, ttl):
        self.config = config
        self.ttl = ttl
        self._listeners = {}

    def addObserver(self, root):
        assert (isinstance(root, str))
        uid = str(uuid.uuid4())
        self._listeners[uid] = {
            "expires": time.time() + 2 * self.ttl,
            "root": root,
            "events": []
        }
        return uid

    def notify(self, eventRoot, eventType, eventUid):
        print("notify eventRoot=%s eventType=%s eventUid=%s" % (eventRoot, eventType, eventUid))
        to_delete = []
        now = time.time()
        for uid in self._listeners:
            rec = self._listeners[uid]
            print("", "rec", rec, eventRoot.startswith(rec["root"]))
            # Auto remove expired listeners.
            if rec["expires"] < now:
                to_delete.append(uid)
                print("Expired %s" % uid)
            elif eventRoot.startswith(rec["root"]):
                print("Adding event %s to %s" % (eventRoot, uid))
                rec["events"].append((eventRoot, eventType, eventUid))
        for uid in to_delete:
            del self._listeners[uid]

    def getEvents(self, uid):
        if not uid in self._listeners:
            raise AbortRequest(404, "Invalid event notification request.")
        rec = self._listeners[uid]
        # Remove if expired, renew otherwise.
        now = time.time()
        if now > rec["expires"] + 2 * self.ttl:
            del self._listeners[uid]
            raise AbortRequest(404, "Invalid event notification request.")
        else:
            rec["expires"] = now + self.ttl
        if rec["events"]:
            result = rec["events"]
            rec["events"] = []
            return result
        else:
            return []


@tornado.web.stream_request_body
class MainHandler(tornado.web.RequestHandler):
    @classmethod
    def initHandler(cls, config):
        cls.poll_granularity = 0.1
        cls.poll_ttl = 1.0

        cls.config = config
        cls.securitymanager = SecurityManager(config)
        cls.eventlistener = EventListener(config, cls.poll_ttl)

    def get(self):
        self.set_header("Content-Type", "text/plain")
        self.set_status(400, "Bad request")
        self.write("Bad request")

    def prepare(self):
        if self.request.method.lower() == "post":
            self.request.connection.set_max_body_size(int(self.config.get("max_file_size", MAX_FILE_SIZE_DEFAULT)))
        if self.config:
            tmpdir = self.config.get("tmpdir", None)
        else:
            tmpdir = None
        # TODO: get content length here?
        try:
            total = int(self.request.headers.get("Content-Length", "0"))
        except:
            total = 0
        self.ps = MultiPartStreamer(total, tmpdir)

    def data_received(self, chunk):
        self.ps.data_received(chunk)

    @classmethod
    def _localpath(cls, homedir, fname):
        """Convert to local path.

        @param homedir: home directory (platform dependent)
        @param fname: path relative to home directory.
            If can either be a string separated with / chars, or a
            list of path items.
        @return: Local filesystem path

        This method will also check if the given fname is safe, see
        the _checksafepath method.

        This method will make sure that the resulting path is inside
        the homedir.

        This method WILL NOT CHECK the safety of the homedir argument.
        This method creates the home directory if it does not exist.
        """
        if not os.path.isdir(homedir):
            os.makedirs(homedir, exist_ok=True)
        return os.path.join(homedir, _checksafepath(fname))

    @classmethod
    def _remove(cls, localpath):
        if os.path.isfile(localpath):
            os.unlink(localpath)
        elif os.path.isdir(localpath):
            shutil.rmtree(localpath)

    def reply(self, values):
        self.set_header("Content-Type", "text/javascript; charset=UTF-8")
        self.write(json.dumps(values))
        self.finish()  # Required because all POST requests are asynchronous.

    def _do_backup(self, perms, homedir):
        assert ("W" in perms)
        response = {}
        cnt = 0
        for part in self.ps.parts:
            filename = part.get_filename()
            if filename:
                cnt += 1
                # Now we know that it is a file.
                selpath = part.get_name()
                _checksafepath(selpath)
                localpath = self._localpath(homedir, selpath)
                if os.path.isfile(localpath):
                    if "D" in perms:
                        self._remove(localpath)
                    else:
                        raise AbortRequest(403, "Not authorized to overwrite.")
                localdir = os.path.split(localpath)[0]
                if not os.path.isdir(localdir):
                    os.makedirs(localdir)
                # Fortunately, these temp files can be closed and renamed freely.
                fsource = part.get_file()
                fsource.close()
                shutil.move(fsource.name, localpath)
                response[selpath] = ""
        if not cnt:
            raise AbortRequest(400, "Bad number of files posted.")
        self.reply(response)

    def _do_restore(self, perms, homedir, fname):
        assert ("R" in perms)
        localpath = self._localpath(homedir, fname)
        # print("_do_restore",homedir,fname,localpath)
        if os.path.isdir(localpath):
            raise AbortRequest(400, "Cannot restore data from a directory.")
        elif not os.path.isfile(localpath):
            print(homedir, fname, localpath)
            raise AbortRequest(404, "Not found.")
        else:
            with open(localpath, 'rb') as fin:
                while True:
                    data = fin.read(16384)
                    if not data:
                        break
                    self.write(data)
        self.finish()  # Required because all POST requests are asynchronous

    def _pollChanges(self, uid, started):
        events = self.eventlistener.getEvents(uid)
        if events:
            self.reply(events)  # Also calls finish(), putting an end to the long poll.
        else:
            now = time.time()
            if now + self.poll_granularity - started > self.poll_ttl:
                # Next poll would be more than poll_ttl
                self.reply([])
            else:
                fnc = functools.partial(self._pollChanges, uid, started)
                tornado.ioloop.IOLoop.instance().add_timeout(
                    time.time() + self.poll_granularity, fnc)

    async def post(self):
        try:
            try:
                self.ps.data_complete()
                params = self.ps.get_parts_by_name("params")
                if not params:
                    raise AbortRequest(400, "Bad request")
                js = params[0].get_payload().decode("UTF-8")
                params = json.loads(js)
                # params = json.loads(self.get_argument("params"))
                if not isinstance(params, dict):
                    raise AbortRequest(400, "Bad request")
                login, pwd = params.get("login", None), params.get("pwd", None)
                action = params.get("action", None)
                user = self.securitymanager.get_user(login)
                if not user:
                    raise AbortRequest(403, "Invalid username or password (#1).")
                if self.securitymanager.check_password(login, pwd):
                    perms = user["perms"]
                    if not perms:
                        raise AbortRequest(403, "Unauthorized to do anything.")
                else:
                    raise AbortRequest(403, "Invalid username or password (#2).")
                # home directory of the user
                homedir = os.path.join(self.config["backup_root"], user["prefix"])

                def checkperm(reqperm, msg="Unauthorized"):
                    for p in reqperm:
                        if p not in perms:
                            raise AbortRequest(403, msg)

                if action == "backup":
                    checkperm("W", "No write access")
                    self._do_backup(perms, homedir)
                elif action == "restore":
                    checkperm("R", "No read access")
                    fname = params.get("fname", None)
                    if not fname:
                        raise AbortRequest(400, "Bad request.")
                    self._do_restore(perms, homedir, fname)
                elif action == "check_exists":
                    checkperm("S", "File listing not allowed")
                    fe = os.path.isfile(self._localpath(
                        homedir, params["fname"]))
                    if fe:
                        self.reply(fe)
                    de = os.path.isdir(self._localpath(
                        homedir, params["fname"]))
                    self.reply(de)
                elif action == "file_exists":
                    checkperm("S", "File listing not allowed")
                    self.reply(os.path.isfile(self._localpath(
                        homedir, params["fname"])))
                elif action == "directory_exists":
                    checkperm("S", "File listing not allowed")
                    self.reply(os.path.isdir(self._localpath(
                        homedir, params["fname"])))

                elif action == "mkdir":
                    checkperm("W")
                    localpath = self._localpath(homedir, params["relpath"])
                    if not os.path.isdir(localpath):
                        # os.mkdir(localpath)
                        os.makedirs(localpath, exist_ok=True)
                    self.reply(0)

                # Synchronization methods
                elif action == "iscasesensitive":
                    checkperm("S")
                    self.reply(LocalFsProvider(homedir).iscasesensitive())
                elif action == "listdir":
                    checkperm("S")
                    _checksafepath(params["relpath"])
                    self.reply(LocalFsProvider(homedir).listdir(
                        params["relpath"]))
                elif action == "getinfo":
                    checkperm("S")
                    _checksafepath(params["root"])
                    root = os.path.join(homedir, params["root"])
                    self.reply(LocalFsProvider(root).getinfo(
                        params["items"], params["encrypted"]))
                elif action == "receivechanges":
                    checkperm("DWS")
                    _checksafepath(params["root"])
                    root = os.path.join(homedir, params["root"])
                    uid = params["uid"]
                    fcopy = []
                    for fitem in params["fcopy"]:
                        op, selpath, atime, mtime, fsize, fpath = fitem
                        _checksafepath(selpath)
                        localpath = self._localpath(homedir, selpath)
                        parts = self.ps.get_parts_by_name(selpath)
                        if len(parts) != 1:
                            raise AbortRequest(400, "Bad number of files posted.")
                        fsource = parts[0].get_file()
                        fsource.flush()
                        fcopy.append([
                            op, selpath, atime, mtime, fsize,
                            fsource.name, LocalFsProvider.SENDER])
                    dst = LocalFsProvider(root)
                    # Not anymore!
                    # dst.file_data_in_change = True
                    [_checksafepath(ditem[1]) for ditem in params["delet"]]
                    dst.receivechanges(iter(params["delet"]))
                    for ditem in params["delet"]:
                        self.eventlistener.notify(
                            params["root"] + "/" + ditem[1], ditem[0], uid)
                    [_checksafepath(ditem[1]) for ditem in params["dcopy"]]
                    dst.receivechanges(iter(params["dcopy"]))
                    for ditem in params["dcopy"]:
                        self.eventlistener.notify(
                            params["root"] + "/" + ditem[1], ditem[0], uid)
                    dst.receivechanges(iter(fcopy))
                    for fitem in params["fcopy"]:
                        self.eventlistener.notify(
                            params["root"] + "/" + fitem[1], fitem[0], uid)
                    self.reply(0)

                # User management methods
                elif action == "getusers":
                    checkperm("A")
                    self.reply(self.securitymanager.get_users())

                elif action == "saveuser":
                    checkperm("A")
                    self.reply(self.securitymanager.save_user(params, login))

                elif action == "deleteuser":
                    checkperm("A")
                    self.reply(self.securitymanager.delete_user(params, login))

                # Other special methods
                elif action == "utcnow":
                    checkperm("T")
                    utcnow = datetime.datetime.utcnow()
                    ticks = time.mktime(utcnow.utctimetuple())
                    self.reply(ticks)

                elif action == "listenchanges":
                    checkperm("N")
                    _checksafepath(params["root"])
                    # Do not add homedir here, listenchanges works on paths relative to the homedir!
                    # root = self._localpath(homedir, params["root"])
                    root = _checksafepath(params["root"])
                    self.reply(self.eventlistener.addObserver(root))

                elif action == "pollchanges":
                    checkperm("N")
                    self._pollChanges(params["uid"], time.time())  # This may reply with a list of changes, or wait...

                else:
                    raise AbortRequest(400, "Invalid action.")
            finally:
                # Don't forget to release temporary files.
                self.ps.release_parts()
        except EInvalidPath as e:
            self.set_status(404, str(e))
            self.reply(str(e))

        except AbortRequest as e:
            # TODO: add logging
            #with open("server.log", "a", encoding="UTF-8") as flog:
            #    traceback.print_exc(file=flog)
            traceback.print_exc()
            self.set_status(e.code, e.msg)
            self.reply(e.msg)
        except Exception:
            # TODO: add logging
            #with open("error.log", "a", encoding="UTF-8") as flog:
            #    traceback.print_exc(file=flog)
            traceback.print_exc()
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Blind Backup server')
    parser.add_argument(
        '-c', '--cfgfile',
        default="server.ini", dest="cfgfile", metavar="CFGFILE",
        help='Config file to be used. Default is server.ini')
    parser.add_argument(
        '-s', '--cfgsection',
        default="default", dest="cfgsection", metavar="CFGSECTION",
        help='Section to be used in config file. Default is "default".')
    parser.add_argument(
        '-p', '--pidfile',
        default=None, dest="pidfile", metavar="PIDFILE",
        help='Specify a file where the process id should be stored. ' + \
             'This file will be automatically removed when the server is ' + \
             'stopped.')

    parser.add_argument(
        '--silent',
        default=False, dest="silent", action="store_true",
        help='Do not display any message when the server is already running, just exit with exit code 0.')

    args = parser.parse_args()

    if args.pidfile:
        if os.path.isfile(args.pidfile):
            pid = open(args.pidfile, "r").read().strip()
            try:
                pid = int(pid)
            except ValueError:
                pid = None
            if pid:
                if psutil.pid_exists(pid):
                    if args.silent:
                        raise SystemExit(0)
                    else:
                        sys.stderr.write(
                            "Is the server still running with pid %s? If not, then please remove %s file.\n" % (
                                pid, args.pidfile))
                        sys.stderr.flush()
                        raise SystemExit(2)


        def remove_pidfile():
            if os.path.isfile(args.pidfile):
                os.unlink(args.pidfile)


        atexit.register(remove_pidfile)
        # TODO: check if the process is alive, exit if it is still running.
        with open(args.pidfile, "w+") as pidfile:
            pidfile.write(str(os.getpid()))

    config = util.load_settings(
        args.cfgfile, args.cfgsection, False)
    if not os.path.isdir(config["backup_root"]):
        parser.error(
            "Root directory '%s' not exists." %
            config["backup_root"])
    # TODO: check keyfile and certfile permissions. Also check if their containing directory is writable.

    MainHandler.initHandler(config)

    application = tornado.web.Application([
        (r"/", MainHandler),
    ])
    try:
        max_buffer_size = int(config["max_buffer_size"])
        max_body_size = int(config["max_body_size"])
    except:
        # 10MB is the default. It does not affect streamed files, only other requests.
        # Streamed files are handled by PostDataStreamer and limited by max_file_size
        max_buffer_size = 10 * 1024 ** 2
        max_body_size = 10 * 1024 ** 2
    http_server = tornado.httpserver.HTTPServer(
        application,
        ssl_options={
            "certfile": localpath(config, "ssl_certfile", None),
            "keyfile": localpath(config, "ssl_keyfile", None),
        },
        max_buffer_size=max_buffer_size,
        max_body_size=max_body_size,
    )
    http_server.listen(int(config["listen_port"]))
    tornado.ioloop.IOLoop.instance().start()
