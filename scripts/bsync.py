#!/usr/bin/env python3
import argparse
import functools
import re
import threading
import time

from blindbackup import cryptfile
from blindbackup.client import BlindFsProvider, create_client
from blindbackup.syncdir import SyncDir, LocalFsProvider, FsProvider
from blindbackup.util import *

DEBUG = False


#
# percent = 0
# def progress_percent(p_up, p_down):
#     global percent
#     if int(p_up) != percent:
#         percent = int(p_up)
#         log(".")

def parse_location(loc, can_create, parser, need_pwd):
    """Parse a location string.

    Return a pair of (fsprovider, settings).
    """
    DEFAULT_LOCALSETTING = {
        "server_url": None,
        "encryptionkey": None,
        "tmpdir": None,
    }
    pat = r"([a-zA-Z][0-9a-zA-Z\_\-]*)://(.*)"
    res = re.match(pat, loc)
    if DEBUG:
        print("parse_location(%s)" % loc)
        print("    pattern=", pat)
        if res:
            print("    res=", res.groups())
        else:
            print("    res=", "<no match>")
    if res:
        cfgsection, path = res.groups()
        settings = load_settings(args.cfgfile, cfgsection, need_pwd)
    else:
        settings = DEFAULT_LOCALSETTING
        path = loc
    if settings["server_url"]:
        if DEBUG:
            print("    server_url=", repr(settings["server_url"]))
        c = create_client(settings)
        if path:
            root = path.split("/")
        else:
            root = []
        provider = BlindFsProvider(c, root,
                                   settings.get("tmpdir", None))
        if not c.directory_exists(path):
            if can_create:
                c("mkdir", relpath=path)
                # else:
                #    parser.error("Remote path does not exist: %s" % loc)
    else:
        if DEBUG:
            print("    server_url=", "<Not given>")
            print("    trying direct path %s" % path)
        if not os.path.isdir(path):
            if can_create:
                os.mkdir(path)
            else:
                parser.error("Not a directory: %s" % path)
        provider = LocalFsProvider(path)
    return provider, settings


class FsEventReducer(threading.Thread):
    """Reduce number of similar events, and forward them to a handler when settled."""

    def __init__(self, can_trigger, onevent):
        self._lock = threading.Lock()
        self._last_changed = 0.0

        self.events = set([])
        self.ttl = 2.0  # Process the events after (about) ttl seconds after the last event.
        self.onevent = onevent
        self.stop_requested = threading.Event()
        self.can_trigger = can_trigger
        threading.Thread.__init__(self)

    def add_event(self, relpath, typ):
        """Add a new filesystem event and schedule for later processing."""
        if not self.stop_requested.is_set():
            # Adding a new event holds the lock for a short amount of time only.
            with self._lock:
                # Convert relpath to immutable hashable tuple
                if isinstance(relpath, list):
                    relpath = tuple(relpath)
                else:
                    assert (isinstance(relpath, tuple))
                # Search for an event that is its parent already.
                idx = 0
                found = False
                while idx <= len(relpath):
                    key = relpath[:idx]
                    if key in self.events:
                        found = True
                        break
                    idx += 1
                if not found:
                    # Parent is not added, add this event and remove all children.
                    self.events.add(relpath)
                    to_reduce = []
                    for event in self.events:
                        if len(event) > len(relpath):
                            if event[:len(relpath)] == relpath:
                                to_reduce.append(event)
                    for event in to_reduce:
                        self.events.remove(event)
                self._last_changed = time.time()
                # print("","",self.events)

    def run(self):
        while not self.stop_requested.is_set():
            time.sleep(self.ttl / 10.0)
            to_process = None
            if self.can_trigger.is_set():
                # Collecting events will be very fast, holds lock.
                with self._lock:
                    now = time.time()
                    if (self.events) and (self._last_changed > 0.0) and (self._last_changed + self.ttl < now):
                        to_process = self.events
                        self.events = set([])
                        self._last_changed = 0.0
            # Processing events can be slow, does not hold lock.
            if to_process:
                # print("FsEventReducer: to_process: ",to_process)
                for event in to_process:
                    if self.stop_requested.is_set():
                        break
                    self.onevent(list(event))

    def request_stop(self):
        self.stop_requested.set()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Synchronize directories.',
        epilog="""Remote location syntax: servername://remotepath

This will take the section "servername" from the client.ini file, or
from the file specified by --cfgfile. See provided client.ini file for details.

It is possible to use remote servers on both sides, and this way
synchronize between two servers. To save network  bandwidth, it is
usually better to synchronize between a server and a local fs. However,
cross-server synchronization may be useful to bypass NAT networks,
firewall boundaries, or simply to recode file data with a different
encryption key.

Notes on possible synchronization modes

a - The normal asymmetric mode will copy any new files or directories
to the destination side. It will also copy changed files from the source
side to the destination side. It will not delete anything anywhere and
it will never copy any changes from the destination side to the source
side.

ad - Asymmetric mode with source deletions synced. This will copy any
    new files or directories to the destination side. This will also
    delete files and directories on the destination side that do not
    exist on the client side. It will not delete anything on the source
    side, and it will never copy any changes from the destination side
    to the source side. You can use this mode to create a mirror of an
    official source.

s - Simple symmetric mode will first do an asymmetric sync from the
    source to destination, then another asymmetric sync from the
    destination to the source. When a file was changed on both sides,
    then the one on the source side is kept, and the one on the
    destination side gets overwritten. This mode will never delete
    anything from anywhere. To delete a file permanently, you must
    delete it on both sides to get rid of it. Otherwise it will be
    restored from the other side. This mode is not very useful in
    practice.

sd - This will first execute a sync from source to dest in "ad" mode,
    then another sync from dest to source in "a" mode. In this mode,
    newly created directories and files, and also file changes are
    synchronized between the two sides. When both sides change a file,
    then source takes precedence. Deletions on the source side will have
    an effect on the destination side, but not the other way. This mode
    is useful when you want to have a "master" source to send changes
    and deletions from, but you also want to allow a "slave" destination
    to send changes (but not deletions).


For dropbox-like synchronization, you need to:

* Use a remote server as the source
* Use a local directory as  the destination
* Use --mode "ad" (for your very first sync)
* Use '--bg-src-to-dst d --bg-dst-to-src d' to auto start syncing when something has changed
* Use '--background-ttl 300' to do a full sync in every 5 minutes

Please note that the synchronization method is somewhat different from dropbox. There are no file journals used.
Most operations (especially deletions) are synced correctly ONLY if you are running auto sync features in both
directions. If you create files in the local folder while the auto sync is not running, then they will probably
be lost. Also if you delete files in the local folder while the auto sync is not running, then they will probably
be restored.


""")

    parser.add_argument(
        '-t', '--cmp-mtime', metavar='CMPMTIME',
        type=str, default="n", dest="cmp_time",
        help='Compare method for modification time. Possible values ' +
             'are: "c"=copy if changed, "n"=copy if source is newer, ' +
             ' "i"=ignore (do not compare). Default is "c". ' +
             'Some systems provide nanosec resolution, others just ' +
             'whole seconds. Comparison is made by one second ' +
             'resolution. When "-t n -s b" is given, -t takes precedence ' +
             'E.g. if the source file is older then it is not copied ' +
             'even if it is bigger than the destination file.'
    )
    parser.add_argument(
        '-s', '--cmp-size', metavar='CMPSIZE',
        type=str, default="c", dest="cmp_size",
        help='Compare method for file size. Possible values are: ' +
             ' "c"=copy if changed, "b"=copy if source is bigger, ' +
             ' "i"=ignore (do not compare). Default is "c". '
    )
    parser.add_argument(
        '-m', '--mode',
        default="ad", dest="mode",
        help='Synchronization mode. Its value is a mode string, with ' +
             'these possible charaters: "a"=assymmetric sync, destination ' +
             'will be synced to match the source. "s"=symmetric sync, sync ' +
             'source to dest, then sync dest to source. ' +
             ' "b"=background mode. Start listening changes on both sides, and synchronize ' +
             'from the side that was changed. "d"=sync deletions ' +
             'too, e.g. files deleted on the source side will be deleted on the ' +
             'destination side. Default mode is "ad". '
    )

    parser.add_argument(
        "-b", '--background-ttl',
        default=None, dest="background_ttl", type=int, metavar="TTL",
        help='Do full background synchronization in every TTL seconds. (TTL must be >0)' +
             'Please note that if you specify this option, then bsync won\'t exit until you terminate it manually.'
    )

    parser.add_argument(
        '--bg-src-to-dst',
        default=None, dest="bg_src_to_dst",
        help='Listen for filesystem changes and synchronize automatically. ' +
             'This option tells that changes in source should be synced to destination. ' +
             'Valid values are: "c" - sync file creations and modifications only. "d" - sync deletions too. ' +
             'Please note that if you specify this option, then bsync won\'t exit until you terminate it manually.'
    )

    parser.add_argument(
        '--bg-dst-to-src',
        default=None, dest="bg_dst_to_src",
        help='Listen for filesystem changes and synchronize automatically. ' +
             'This option tells that changes in destination should be synced to source. ' +
             'Valid values are: "c" - sync file creations and modifications only. "d" - sync deletions too. ' +
             'Please note that if you specify this option, then bsync won\'t exit until you terminate it manually.'
    )

    parser.add_argument(
        '-c', '--cfgfile',
        default="client.ini", dest="cfgfile", metavar="CFGFILE",
        help='Config file to be used. Default is client.ini ' +
             'This is only used when the destination is a remote server.'
    )

    parser.add_argument(
        "-v", "--verbose",
        dest="verbose", default=False, action="store_true",
        help="Verbose: print operations to stdout."
    )

    parser.add_argument(
        "-d", "--debug",
        dest="debug", default=False, action="store_true",
        help="Debug: print debug messages to stdout."
    )

    parser.add_argument(
        dest="srcpath", metavar="SOURCELOCATION",
        help="Source location."
    )
    parser.add_argument(
        dest="dstpath", metavar="DESTINATIONPATH",
        help="Destination location."
    )

    args = parser.parse_args()
    DEBUG = args.debug
    options = {}

    mtflag = args.cmp_time.lower()
    if mtflag == "c":
        options["mtcompare"] = SyncDir.CMP_CHANGED
    elif mtflag == "n":
        options["mtcompare"] = SyncDir.CMP_NEWER
    elif mtflag == "i":
        options["mtcompare"] = SyncDir.CMP_IGNORE
    else:
        parser.error("Invalid value for --cmp-time")

    stflag = args.cmp_size.lower()
    if stflag == "c":
        options["stcompare"] = SyncDir.CMP_CHANGED
    elif stflag == "b":
        options["stcompare"] = SyncDir.CMP_BIGGER
    elif stflag == "i":
        options["stcompare"] = SyncDir.CMP_IGNORE
    else:
        parser.error("Invalid value for --cmp-size")

    if options["stcompare"] == SyncDir.CMP_IGNORE and \
                    options["mtcompare"] == SyncDir.CMP_IGNORE:
        parser.error("Cannot ignore both mtime and fsize.")

    mode = args.mode.strip().lower()
    if "a" in mode:
        symmetric = False
    elif "s" in mode:
        symmetric = True
    else:
        parser.error('Mode string must contain "a" or "s".')

    if args.bg_src_to_dst:
        if args.bg_src_to_dst not in ["c", "d"]:
            parser.error("Invalid values for --bg-src-to-dst")

    if args.bg_dst_to_src:
        if args.bg_dst_to_src not in ["c", "d"]:
            parser.error("Invalid values for --bg-dst-to-src")

    if args.background_ttl is not None:
        if args.background_ttl <= 0:
            parser.error("Invalid value for --background-ttl: must be a positive integer.")

    # TODO: how to tell if need_pwd should be true?
    src, srcsettings = parse_location(args.srcpath, False, parser, False)
    dst, dstsettings = parse_location(args.dstpath, True, parser, False)

    syncdir = SyncDir()
    senckey = srcsettings["encryptionkey"]
    if senckey and senckey.strip():
        srckey = cryptfile.hashkey(senckey.strip())
    else:
        srckey = None
    denckey = dstsettings["encryptionkey"]
    if denckey and denckey.strip():
        dstkey = cryptfile.hashkey(denckey.strip())
    else:
        dstkey = None
    logchanges = None

    can_trigger = threading.Event()
    can_trigger.set()

    sync_lock = threading.Lock()


    def do_sync(reason):
        with sync_lock:
            # src -> dst
            if args.verbose:
                logchanges = dst.logchanges
                if "d" in mode:
                    print("%s: %s --(ad)--> %s" % (reason, args.srcpath, args.dstpath))
                else:
                    print("%s: %s --(a)--> %s" % (reason, args.srcpath, args.dstpath))
            options["syncdelete"] = "d" in mode
            can_trigger.clear()
            try:
                syncdir.sync(src, dst, options, srckey, dstkey, logchanges)
                if symmetric:
                    # dst -> src
                    # Anything that was deleted on the dest side is already restored
                    # from the source side. So syncing deletions is useless here.
                    # However, we turn this off here because there can be somebody
                    # deleting files in the background...
                    options["syncdelete"] = False
                    if args.verbose:
                        print("%s: %s <--(a)-- %s" % (reason, args.srcpath, args.dstpath))
                        logchanges = src.logchanges
                    syncdir.sync(dst, src, options, dstkey, srckey, logchanges)
            finally:
                can_trigger.set()


    def do_bg_sync():
        # Finally, we do normal background sync, if requested.
        if args.background_ttl and args.background_ttl > 0:
            elapsed = 0.0
            while True:
                time.sleep(args.background_ttl / 10.0)
                elapsed += args.background_ttl / 10.0
                if (elapsed >= args.background_ttl) and can_trigger.is_set():
                    do_sync("BGSYNC")
                    elapsed = 0.0
        else:
            while True:
                time.sleep(1)


    # First we do a normal sync as requested
    do_sync("SYNC")

    # Then we setup filesystem change listeners.

    if args.bg_src_to_dst or args.bg_dst_to_src:
        # If any background processing is asked for...

        def onchange_any(changed, other, changedkey, otherkey, syncdelete, relpath):
            # This method is called when events are settled for a while.
            # FsEventReducer makes sure there that only events for top level paths are fired.
            options["syncdelete"] = syncdelete
            # Should already popped BEFORE it is added to eventreducer.
            # Otherwise the same path could be synchronized multiple times!
            # if relpath:
            #    relpath.pop()

            # print(relpath,"PROCESS EVENT")

            print("EVENT SYNC", changed.root, relpath, "->", other.root, relpath)

            drilled_src = changed.clone()
            drilled_src.drill(relpath)

            drilled_dst = other.clone()
            drilled_dst.decryptionkey = changedkey
            drilled_dst.encryptionkey = otherkey

            drill_path = drilled_dst.recrypt_path_items(relpath)
            drilled_dst.drill(drill_path)
            syncdir.sync(drilled_src, drilled_dst, options, changedkey, otherkey, logchanges)


        reducers = []
        if args.bg_src_to_dst:
            reducer_src_to_dst = FsEventReducer(
                can_trigger,
                functools.partial(onchange_any, src, dst, srckey, dstkey, args.bg_src_to_dst == "d")
            )
            reducers.append(reducer_src_to_dst)
            reducer_src_to_dst.start()
        if args.bg_dst_to_src:
            reducer_dst_to_src = FsEventReducer(
                can_trigger,
                functools.partial(onchange_any, dst, src, dstkey, srckey, args.bg_dst_to_src == "d")
            )
            reducers.append(reducer_dst_to_src)
            reducer_dst_to_src.start()


        def onchange_src_to_dst(sender, path, typ, uid):
            relpath = sender.get_event_relpath(path)
            if (typ == FsProvider.DELETE) or (typ == FsProvider.DIRECTORY):
                relpath = relpath[:-1]
            # print ("onchange_src_to_dst",path,relpath,typ)
            reducer_src_to_dst.add_event(relpath, typ)


        def onchange_dst_to_src(sender, path, typ, uid):
            relpath = sender.get_event_relpath(path)
            if (typ == FsProvider.DELETE) or (typ == FsProvider.DIRECTORY):
                relpath = relpath[:-1]
            # print ("reducer_dst_to_src",path,relpath,typ)
            reducer_dst_to_src.add_event(relpath, typ)


        listeners = []  # A list of listeners that listen for filesystem changes.
        if args.bg_src_to_dst:
            listeners.append(src.listenchanges(onchange_src_to_dst))
        if args.bg_dst_to_src:
            listeners.append(dst.listenchanges(onchange_dst_to_src))
        try:
            do_bg_sync()
        finally:
            for listener in listeners:
                listener.request_stop()
            for reducer in reducers:
                reducer.request_stop()
            if args.verbose:
                print("Stopping filesystem listeners...")
            for listener in listeners:
                listener.join()
            if args.verbose:
                print("Stopping event reducers...")
            for reducer in reducers:
                reducer.join()
    elif (args.background_ttl is not None) and (args.background_ttl > 0):
        do_bg_sync()
