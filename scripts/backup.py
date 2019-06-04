#!/usr/bin/env python3
import argparse
import datetime
import functools
import os.path
import re
import time

from blindbackup import client, cryptfile, util

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Backup a file securely.')
    parser.add_argument(
        'fpath', metavar='FILEPATH', type=str,
        help='Path of the file to be backed up. Compressed into a zip ' +
             'file and possibly encoded.')
    parser.add_argument(
        '-n', '--fname', metavar='FILENAME',
        type=str, default=None, dest="fname",
        help='Filename on backup server. ' +
             'If not given, taken from the file path. ')
    parser.add_argument(
        '-e', '--extname', metavar="EXTENSION",
        type=str, default=None, dest="extname",
        help='Add this extension to the name of the file. Can only be combined with --timestampname and --no-compress')
    parser.add_argument(
        '-t', '--timestampname',
        default=False, action="store_true", dest="timestampname",
        help='Use local timestamp for filename on backup server. ')
    parser.add_argument(
        '-q', '--quiet',
        default=False, action="store_true", dest="quiet",
        help='Do not show the upload progress indicator.')
    parser.add_argument(
        '-p', '--prefix', metavar='FILENAME',
        type=str, default=None, dest="prefix",
        help='Prefix (directory) for file name. Can only be combined ' +
             'with --timestampname. ')
    parser.add_argument(
        '--no-compress',
        default=False, action="store_true", dest="no_compress",
        help='Do not compress the file. It can only be used if the file to be backed up is a regular file.')
    parser.add_argument(
        '--success-message-file',
        default=None, dest="successmessagefile",
        help='Success message file to be displayed and waited for when ' +
             'successful.')
    parser.add_argument(
        '-c', '--cfgfile',
        default="client.ini", dest="cfgfile", metavar="CFGFILE",
        help='Config file to be used. Default is client.ini')
    parser.add_argument(
        '-s', '--cfgsection',
        default="default", dest="cfgsection", metavar="CFGSECTION",
        help='Section to be used in config file. Default is "default".')
    parser.add_argument(
        '-o', '--overwrite',
        default=False, dest="overwrite", action="store_true",
        help="Overwrite existing files on the server. If you don't " +
             "Specify this flag, then the file will not be uploaded if " +
             "it already exists on the server."
    )

    args = parser.parse_args()
    settings = util.load_settings(args.cfgfile, args.cfgsection, True)
    c = client.create_client(settings)

    if args.fname is not None and args.timestampname:
        parser.error("--fname and --timestampname cannot be combined.")

    if args.prefix and not args.timestampname:
        parser.error("--prefix can only be used with --timestampname.")

    if args.extname and (not args.timestampname or not args.no_compress):
        parser.error("--extname can only be used with --timestampname AND --no-compress.")

    if args.prefix:
        if "\\" in args.prefix:
            parser.error("Use '/' characters for separation, never '\\'")
        if args.prefix.startswith("/") or args.prefix.startswith(".") or \
                        ".." in args.prefix or "?" in args.prefix or \
                        "*" in args.prefix:
            parser.error(
                "Invalid prefix: cannot start with '/' or '.' and " +
                "cannot contain '..','*','?'")

    if args.extname:
        if not re.match(r"[0-9a-zA-Z]+", args.extname):
            parser.error(
                "Extension can only contain digits and english letters (a-z)")

    if os.path.isfile(args.fpath) or os.path.isdir(args.fpath):
        fpath = args.fpath
    else:
        parser.error("No such file: %s" % args.fpath)

    if args.no_compress and os.path.isdir(args.fpath):
        parser.error("--no-compress cannot be used with a directory. Only with a regular file.")

    last_update = -1
    last_eta_percent = 0.0
    last_eta = time.time()
    _p_cnt = 0


    def progress_percent(p_up, p_down):
        global _p_cnt
        global last_update
        global last_eta
        global last_eta_percent

        global args
        if not args.quiet:
            now = time.time()
            if now - last_update > 2:
                _p_cnt += 1
                last_update = now
                if _p_cnt < 10:
                    util.log(".")
                else:
                    _p_cnt = 0
                    util.log("%.1f%%" % (int(p_up * 10.0) / 10.0))

                    if now - last_eta < 60.0:
                        percent_per_sec = (p_up - last_eta_percent) / (now - last_eta)
                        remaining_percent = 100.0 - p_up
                        remaining_sec = remaining_percent / percent_per_sec
                        s_remaining = str(datetime.timedelta(seconds=remaining_sec))
                        p_idx = s_remaining.rfind(".")
                        if p_idx > 0:
                            s_remaining = s_remaining[:p_idx]
                        util.log(" ETA=%s " % s_remaining)
                        last_eta = now
                        last_eta_percent = p_up


    if args.fname is None:
        if args.timestampname:
            fname = str(datetime.datetime.now())
            fname = fname.replace("-", ""). \
                        replace(":", "").replace(" ", "_")[:15]
            if args.prefix:
                fname = args.prefix + "/" + fname
        else:
            fname = os.path.split(args.fpath)[1]
        if not args.no_compress:
            fname += ".zip"
        elif args.extname:
            fname += "." + args.extname
    else:
        fname = args.fname

    try:
        if not args.overwrite:
            try:
                if c.file_exists(fname):
                    print("ERROR: %s already exists on server." % fname)
                    raise SystemExit(-1)
            except client.ReqError as e:
                print("WARNING: %s: %s" % (e.code, e.msg.decode("UTF-8")))

        if args.no_compress:
            enckey = settings.get("encryptionkey", None)
            if enckey:
                enckey = cryptfile.hashkey(enckey)
            if enckey:
                print("Encrypting...")
                fenc = util.create_tmp_file(settings)
                cryptfile.encrypt_file(enckey, args.fpath, fenc)
                try:
                    print("Sending file %s to server %s under name %s " % (
                        args.fpath, settings["server_url"], fname))
                    fname = "/".join(map(
                        functools.partial(cryptfile.encrypt_filename, enckey),
                        fname.split("/")
                    ))
                    res = c.send_backup(fname, fenc, progress_percent)
                finally:
                    os.unlink(fenc)
            else:
                print("Sending file %s to server %s under name %s " % (
                    args.fpath, settings["server_url"], fname))
                res = c.send_backup(fname, args.fpath, progress_percent)

            if res[fname]:
                util.log(" ERROR: " + res[fname] + "\n")
                raise SystemExit(-1)
            else:
                util.log(" OK\n")
                if args.successmessagefile:
                    print(open(args.successmessagefile, "r").read())
                    input("[ENTER]")
        else:
            print("Compressing...")
            fzip = util.create_tmp_file(settings)
            fenc = None
            try:
                util.make_zipfile(fzip, args.fpath)
                enckey = settings.get("encryptionkey", None)
                if enckey:
                    enckey = cryptfile.hashkey(enckey)
                if enckey:
                    print("Encrypting...")
                    fenc = util.create_tmp_file(settings)
                    cryptfile.encrypt_file(enckey, fzip, fenc)
                    try:
                        print("Sending file %s to server %s under name %s " % (
                            args.fpath, settings["server_url"], fname))
                        fname = "/".join(map(
                            functools.partial(cryptfile.encrypt_filename, enckey),
                            fname.split("/")
                        ))
                        res = c.send_backup(fname, fenc, progress_percent)
                    finally:
                        os.unlink(fenc)
                else:
                    print("Sending file %s to server %s under name %s " % (
                        args.fpath, settings["server_url"], fname))
                    res = c.send_backup(fname, fzip, progress_percent)

                if res[fname]:
                    util.log(" ERROR: " + res[fname] + "\n")
                    raise SystemExit(-1)
                else:
                    util.log(" OK\n")
                    if args.successmessagefile:
                        print(open(args.successmessagefile, "r").read())
                        input("[ENTER]")
            finally:
                os.unlink(fzip)

    except client.ReqError as e:
        print("ERROR: %s: %s" % (e.code, e.msg.decode("UTF-8")))
        raise SystemExit(-1)
