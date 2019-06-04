#!/usr/bin/env python3
import argparse

from blindbackup import client
from blindbackup.client import create_client
from blindbackup.util import *

percent = 0


def progress_percent(p_up, p_down):
    global percent
    if int(p_up) != percent:
        percent = int(p_up)
        log(".")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Restore from a backup.')

    parser.add_argument(
        '-c', '--cfgfile',
        default="client.ini", dest="cfgfile", metavar="CFGFILE",
        help='Config file to be used. Default is client.ini')
    parser.add_argument(
        '-s', '--cfgsection',
        default="default", dest="cfgsection", metavar="CFGSECTION",
        help='Section to be used in config file. Default is "default".')

    # ~ parser.add_argument(
    # ~ '--success-message-file',
    # ~ default=None, dest="successmessagefile",
    # ~ help='Success message file to be displayed and waited for when ' +
    # ~ 'successful.')
    # ~
    # ~ parser.add_argument(
    # ~ '-o', '--overwrite',
    # ~ default=False, dest="overwrite", action="store_true",
    # ~ help="Overwrite existing files on the server. If you don't " +
    # ~ "Specify this flag, then the file will not be uploaded if " +
    # ~ "it already exists on the server."
    # ~ )

    parser.add_argument('action', metavar='ACTION', type=str,
                        help='Action to perform. One of: listdir, ls , restore-first, rf,' + \
                             'restore_last, rl, restore, r'
                        )

    parser.add_argument('arguments', metavar='ARG', type=str, nargs="+",
                        help='Other arguments for the action.'
                        )

    args = parser.parse_args()

    settings = load_settings(args.cfgfile, args.cfgsection, False)
    c = create_client(settings)

    try:
        action = args.action.strip().lower()
        arguments = args.arguments
        if action in ["listdir", "ls"]:
            relpath = arguments[0].split("/")
            if c.directory_exists(relpath):
                dnames, fnames = c.listdir(relpath)
                for dname in sorted(dnames):
                    print(dname + "/")
                for fname in sorted(fnames):
                    print(fname)
            else:
                print("No such directory: ", relpath)
                raise SystemExit(-1)
        elif action in ["restore-first", "rf", "restore-last", "rl", "restore", "r"]:
            relpath = arguments[0].split("/")
            if c.directory_exists(relpath):
                dnames, fnames = c.listdir(relpath)
                if fnames:
                    to_restore = sorted(fnames)[-1]
                    print("to_restore=", to_restore)
                else:
                    print("No file at all in: ", relpath)
                    raise SystemExit(-1)
            else:
                print("No such directory: ", relpath)
                raise SystemExit(-1)
    except client.ReqError as e:
        print("ERROR: %s: %s" % (e.code, e.msg.decode("UTF-8")))
        raise SystemExit(-1)
