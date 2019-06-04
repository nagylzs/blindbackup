import sys
import time

from blindbackup.cryptfile import *


def test_pad_unpad():
    some_name = b"01234"
    padded_name = pad(some_name)
    assert padded_name == some_name + b'\x1b' * (32 - len(some_name))
    unpadded_name = unpad(padded_name)
    assert unpadded_name == some_name


def test_hashkey():
    some_key = "01234"
    hashed_key = hashkey(some_key)
    assert hashed_key == \
           b'\xc5e\xfe\x03\xca\x9bbB\xe0\x1d\xfd\xde\xfe\x9b\xba=\x98\xb2p\xe1\x9c\xd0/\xd8\\\xea\xf7^+%\xbf\x12'


def test_encrypt_filename():
    for filename in ["test.txt", "megszentségteleníthetetlenségeskedésetekért.txt"]:
        key = "blabla"
        hashked_key = hashkey(key)
        enc_name_1 = encrypt_filename(hashked_key, filename)
        enc_name_2 = encrypt_filename(hashked_key, filename)
        assert enc_name_1 == enc_name_2
        dec_name_1 = decrypt_filename(hashked_key, enc_name_1)
        dec_name_2 = decrypt_filename(hashked_key, enc_name_2)
        assert dec_name_1 == dec_name_2 == filename


def test_encrypt_file():
    infile = "test.dat"
    outfile = "test.enc"
    checkfile = "test2.dat"

    # noinspection PyDefaultArgument
    def progress(total, actual, _last=[0]):
        time.sleep(0.01)  # Make it slower so that we can see the progress
        percent = round(actual * 100.0 / total)
        if _last[0] != percent:
            _last[0] = percent
            sys.stdout.write('.')
            sys.stdout.flush()

    orig_data = token_bytes(99999)
    with open(infile, "wb+") as fout:
        fout.write(orig_data)
    try:
        key = "abcd"
        hkey = hashkey(key)
        encrypt_file(hkey, infile, outfile, progressfunc=progress)
        try:
            decrypt_file(hkey, outfile, checkfile, progressfunc=progress)
            try:
                check_data = open(checkfile, "rb").read()
                assert orig_data == check_data
            finally:
                os.unlink(checkfile)
        finally:
            os.unlink(outfile)
    finally:
        os.unlink(infile)


def test_recrypt_file():
    infile = "test.dat"
    enc1 = "test.enc1"
    enc2 = "test.enc2"
    checkfile = "test2.dat"
    key1 = "abcd"
    key2 = "efgh"

    hkey1 = hashkey(key1)
    hkey2 = hashkey(key2)

    # noinspection PyDefaultArgument
    def progress(total, actual, _last=[0]):
        time.sleep(0.01)  # Make it slower so that we can see the progress
        percent = round(actual * 100.0 / total)
        if _last[0] != percent:
            _last[0] = percent
            sys.stdout.write('.')
            sys.stdout.flush()

    orig_data = token_bytes(99999)
    with open(infile, "wb+") as fout:
        fout.write(orig_data)
    try:
        encrypt_file(hkey1, infile, enc1)
        try:
            recrypt_file(hkey1, hkey2, enc1, enc2, progressfunc=progress)
            try:
                decrypt_file(hkey2, enc2, checkfile)
                check_data = open(checkfile, "rb").read()
                assert check_data == orig_data
            finally:
                os.unlink(enc2)
                pass
        finally:
            os.unlink(enc1)
            pass
    finally:
        os.unlink(infile)
        pass

