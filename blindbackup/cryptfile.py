"""Encrypting and decrypting files with AES.

Tries to be safe, portable and fast.

Safety: uses AES keyed by sha256 hash of the original password.
Portability: uses only pycrypto and base CPython
Speed: uses CBC mode, so whole blocks are encrypted with pycrypto.

Because of the CBC mode, files are amended with random data to reach
whole blocksizes (40 bytes). So there must be a way to tell the original
file size somehow. We do not store the original size in an encpryted
form, because that would be an (almost) known value and it could be
used to crack the encryptionkey. So the original file size is stored
unencrypted at the beginning of the file, along with a random vector
that is used to initialize the AES chiper. It also means that you
will get totally different results if you encrypt the same file
over and over. It makes harder to crack the encryption key when
the attacker has access to a process that can encrypt arbitrary
amounts of (known) data for him.
"""
import os
import struct
import contextlib
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

BS = algorithms.AES.block_size // 8
IV = b'\x00' * BS
CHUNK_SIZE = 128 * BS

try:
    # noinspection PyPackageRequirements
    from secrets import token_bytes
except ImportError:
    from os import urandom as token_bytes


def pad(b):
    padder = padding.PKCS7(256).padder()
    return padder.update(b) + padder.finalize()


def unpad(b):
    unpadder = padding.PKCS7(256).unpadder()
    return unpadder.update(b) + unpadder.finalize()


def hashkey(plainkey):
    """Hash a normal string into a binary hash value."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(plainkey.encode("UTF-8"))
    return digest.finalize()


def encrypt_filename(hashed_key, filename):
    """Encrypts a filename with the given key.

    @param hashed_key: The encryption key. A binary string that has
        BS length. See hashkey().
    @param filename: A normal (non-binary) string containing a
        filename of arbitrary length.
    @return an ascii (non-binary) string that represents the
        encrypted filename

    There is no randomness in this function. If you encrypt the same
    filename with the same key twice, you will get the same result.
    """
    # assert len(hashed_key) == 32
    padded_data = pad(filename.encode("UTF-8"))
    cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(ct, b"+-").decode("ASCII")


def decrypt_filename(hashed_key, enc_filename):
    # assert len(hashed_key) == 32
    ct = base64.b64decode(enc_filename.encode("ASCII"), b"+-")
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(IV), backend=backend)
    return unpad(cipher.decryptor().update(ct)).decode("UTF-8")


def get_origsize(fpath):
    """Get original file size of a file."""
    with open(fpath, 'rb') as infile:
        return struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]


def encrypt_file(hashed_key, in_filename, out_filename=None, chunksize=64 * 1024, progressfunc=None):
    """ Encrypts a file using AES (CBC mode) with the given key.

    There is some randomness in the encryption. If you encrypt the
    same file two times with the same key, then you will get
    different contents.

    :param hashed_key: The hashed encryption key, as returned by hashkey
    :param in_filename: Name of the input file
    :param out_filename: If None, '<in_filename>.enc' will be used.
    :param chunksize: Sets the size of the chunk which the function uses to read and encrypt the file. Larger chunk
        sizes can be faster for some files and machines. chunksize must be divisible by AES.block_size (16)
    :param progressfunc: When given this will be called back with (total, processed)
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = token_bytes(BS)
    cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    total = os.path.getsize(in_filename)
    processed = 0

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', total))
            outfile.write(iv)
            if progressfunc is not None:
                progressfunc(total, 0)
            while True:
                chunk = infile.read(chunksize)
                lc = len(chunk)
                processed += lc
                if not lc:
                    break
                if lc % BS:
                    chunk += token_bytes(BS - lc % BS)
                outfile.write(encryptor.update(chunk))
                if progressfunc is not None:
                    progressfunc(total, processed)
            assert processed == total
            outfile.write(encryptor.finalize())


def decrypt_file(hashed_key, in_filename, out_filename=None, chunksize=CHUNK_SIZE, progressfunc=None):
    """ Decrypts a file using AES (CBC mode) with the given key.

    Parameters are similar to encrypt_file, with one difference: out_filename, if not supplied will be in_filename
    without its last extension (i.e. if in_filename is 'aaa.zip.enc' then out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(BS)
        cipher = Cipher(algorithms.AES(hashed_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        progress = 0
        if progressfunc is not None:
            progressfunc(origsize, 0)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if not chunk:
                    break
                chunk = decryptor.update(chunk)
                progress += len(chunk)
                outfile.write(chunk)
                if progressfunc is not None:
                    progressfunc(origsize, progress)
            chunk = decryptor.finalize()
            outfile.write(chunk)
            progress += len(chunk)
            if progress < origsize:
                raise IOError("Trying to decrypt a corrupt, truncated file")
            outfile.truncate(origsize)
        if progressfunc:
            progressfunc(origsize, origsize)


def recrypt_file(decrypt_hkey, encrypt_hkey, in_filename, out_filename, chunksize=CHUNK_SIZE, progressfunc=None):
    """ Decrypt + encrypt a file with the given decryption and encryption key.

    :param decrypt_hkey: Hashed key for decryption
    :param encrypt_hkey: Hashed key for encryption
    :param in_filename: Input filename containing original encrypted data
    :param out_filename: Out filename containing new re-encrypted data
    :param chunksize: Sets the size of the chunk which the function uses to read and recrypt the file. Larger chunk
        sizes can be faster for some files and machines. chunksize must be divisible by AES.block_size (16)
    :param progressfunc: When given this will be called back with (total, processed)
    """
    with open(in_filename, 'rb') as infile:
        total = os.path.getsize(in_filename)
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv1 = infile.read(BS)
        progress = struct.calcsize('Q') + BS
        cipher = Cipher(algorithms.AES(decrypt_hkey), modes.CBC(iv1), backend=backend)
        decryptor = cipher.decryptor()

        iv2 = token_bytes(BS)
        cipher = Cipher(algorithms.AES(encrypt_hkey), modes.CBC(iv2), backend=backend)
        encryptor = cipher.encryptor()

        if progressfunc:
            progressfunc(total, 0)

        with open(out_filename, 'wb') as outfile:
            # Write out the same original size
            outfile.write(struct.pack('<Q', origsize))
            outfile.write(iv2)
            while True:
                chunk = infile.read(chunksize)
                lc = len(chunk)
                if not lc:
                    break
                progress += lc
                if progressfunc:
                    progressfunc(total, progress)
                outfile.write(encryptor.update(decryptor.update(chunk)))
            chunk = encryptor.update(decryptor.finalize())
            progress += len(chunk)
            outfile.write(chunk)
            chunk = encryptor.finalize()
            progress += len(chunk)
            outfile.write(chunk)
            if progress != total:
                raise IOError("Trying to recrypt a corrupt, truncated file")
        if progressfunc:
            progressfunc(total, total)


@contextlib.contextmanager
def encrypted_file(hashed_key, fpath):
    """Encrypt a file temporarily on-the-fly."""
    tmp_path = fpath + ".~tmp"
    try:
        encrypt_file(hashed_key, fpath, tmp_path)
        yield tmp_path
    finally:
        os.unlink(tmp_path)


@contextlib.contextmanager
def decrypted_file(hashed_key, fpath):
    """Decrypt a file temporarily on-the-fly."""
    tmp_path = fpath + ".~tmp"
    try:
        decrypt_file(hashed_key, fpath, tmp_path)
        yield tmp_path
    finally:
        os.unlink(tmp_path)


@contextlib.contextmanager
def recrypted_file(de_key, en_key, fpath):
    """Re-crypt a file temporarily on-the-fly."""
    tmp_path = fpath + ".~tmp"
    try:
        recrypt_file(de_key, en_key, fpath, tmp_path)
        yield tmp_path
    finally:
        os.unlink(tmp_path)
