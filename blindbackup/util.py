import os
import sys
import getpass
import subprocess
import configparser
import tempfile
import zipfile


def localpath(settings, key, defval=None):
    """Get a path value relative to the settings ini file."""
    if key in settings:
        path = settings[key]
        if os.path.isabs(path):
            return path
        else:
            return os.path.join(settings['inidir'], path)
    else:
        return defval


def load_settings(inipath, section, need_pwd):
    # TODO: check ini file permissions here. Issue a warning if there is a password in the file
    # that can be read by anyone
    config = configparser.ConfigParser()
    config.read(inipath)
    settings = {}
    for key in config[section]:
        settings[key] = config[section][key]
    if need_pwd and "password" not in settings:
        settings["password"] = getpass.getpass("Password:")
    settings["inipath"] = inipath
    settings["inidir"] = os.path.dirname(os.path.abspath(inipath))
    return settings


def create_tmp_file(settings):
    if settings.get("tmpdir", None):
        fout = tempfile.NamedTemporaryFile(
            dir=localpath(settings, "tmpdir", None),
            delete=False)
    else:
        fout = tempfile.NamedTemporaryFile(delete=False)
    fout.close()
    return fout.name


def create_tmp_file_for(fpath):
    """Create a named temporary file for a given file path.

    The temporary file will be created in the same directory, but its
    name will always be random. This is required because pycurl will
    post the file with its original filename in the request. The client
    can encrypt filenames and file data before sending it to the server.
    The server should not know anything about the file. So it would be
    a bad idea to send an "original filename" whose prefix is the
    real original filename.
    """
    if fpath:
        dpath, fname = os.path.split(fpath)
        return create_tmp_file({"tmpdir": dpath})
    else:
        return create_tmp_file({})


def make_zipfile(output_filename, source):
    if os.path.isdir(source):
        relroot = os.path.abspath(os.path.join(source, os.pardir))
        with zipfile.ZipFile(
                output_filename, "w", zipfile.ZIP_DEFLATED,
                allowZip64=True) as zf:
            for root, dirs, files in os.walk(source):
                # add directory (needed for empty dirs)
                zf.write(root, os.path.relpath(root, relroot))
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if os.path.isfile(fpath):  # regular files only
                        arcname = os.path.join(os.path.relpath(
                            root, relroot), fname)
                        # TODO: add progress function here?
                        # See http://stackoverflow.com/questions/4341584/extract-zipfile-using-python-display-progress-percentage
                        zf.write(fpath, arcname)
    else:
        with zipfile.ZipFile(output_filename, "w", zipfile.ZIP_DEFLATED,
                             allowZip64=True) as zf:
            zf.write(source, os.path.split(source)[1])


def log(s):
    sys.stdout.write(s)
    sys.stdout.flush()


# http://stackoverflow.com/questions/6631299/python-opening-a-folder-in-explorer-nautilus-mac-thingie
if sys.platform == 'darwin':
    def openFolder(path):
        subprocess.check_call(['open', '--', path])
elif sys.platform == 'linux2':
    def openFolder(path):
        subprocess.check_call(['gnome-open', '--', path])
elif sys.platform == 'win32':
    def openFolder(path):
        subprocess.check_call(['explorer', path])
