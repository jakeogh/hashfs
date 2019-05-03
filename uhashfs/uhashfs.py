"""Module for uHashFS class."""

from pathlib import Path
import hashlib
import io
import os
import sys
import time
from tempfile import NamedTemporaryFile
import binascii
import redis
import attr


def compact(items):
    """Return only truthy elements of `items`."""
    return [item for item in items if item]


def unshard(path):
    """Unshard path to determine hash value."""
    try:
        assert os.path.sep in path
    except AssertionError:
        raise ValueError('Path must be absolute.')

    return path.split(os.path.sep)[-1]


def hash_readable(handle, algorithm, tmp):
    block_size = 256 * 128 * 2
    hasher = hashlib.new(algorithm)
    for chunk in iter(lambda: handle.read(block_size), b''):
        hasher.update(chunk)
        if tmp:
            tmp.write(chunk)
    if tmp:
        tmp.close()
    return hasher.digest()


def hash_file(path, algorithm, tmp):
    with open(path, 'rb') as handle:
        digest = hash_readable(handle, algorithm, tmp)
    return digest


def hash_file_handle(handle, algorithm, tmp):
    pos = handle.tell()
    digest = hash_readable(handle, algorithm, tmp)
    handle.seek(pos)
    return digest


def path_is_parent(parent, child):
    #print("parent:", parent.__repr__())
    #print("child:", child.__repr__())
    parent = parent.expanduser().resolve()
    child = child.expanduser().resolve()
    return os.path.commonpath([parent]) == os.path.commonpath([parent, child])


@attr.s(auto_attribs=True, kw_only=True)
class uHashFS():
    """Content addressable file manager.

    Attributes:
        root (str): Directory path used as root of storage space.
        tmproot (str): Optional directory used for NamedTemporaryFile storage
            space. Defaults to the hashfs root. Must be on the same filesystem.
        depth (int, optional): Depth of subfolders to create when saving a
            file.
        width (int, optional): Width of each subfolder to create when saving a
            file.
        algorithm (str): Hash algorithm to use when computing file hash.
            Algorithm should be available in ``hashlib`` module. Defaults to
            ``'sha256'``.
        fmode (int, optional): File mode permission to set when adding files to
            directory. Defaults to ``0o664`` which allows owner/group to
            read/write and everyone else to read.
        dmode (int, optional): Directory mode permission to set for
            subdirectories. Defaults to ``0o755`` which allows owner/group to
            read/write and everyone else to read and everyone to execute.
    """
    root: str = attr.ib(converter=Path)
    tmproot: str = attr.ib(converter=Path)
    #tmproot: str = attr.ib(converter=Path, default=root)
    depth: int = 4
    width: int = 1
    algorithm: str = 'sha3_256'
    fmode: int = 0o444
    dmode: int = 0o755
    verbose: bool = False
    redis: bool = False

    def __attrs_post_init__(self):
        self.root = self.root.resolve()
        self.digestlen = hashlib.new(self.algorithm).digest_size
        self.hexdigestlen = self.digestlen * 2
        self.emptydigest = getattr(hashlib, self.algorithm)(b'').digest()
        self.emptyhexdigest = self.emptydigest.hex()
        if self.redis:
            self.redis = redis.StrictRedis(host='127.0.0.1')
            self.rediskey = ':'.join(["uhashfs", str(self.root), self.algorithm]) + '#'
            print("self.rediskey:", self.rediskey)
        assert len(self.emptydigest) == self.digestlen
        assert len(self.emptyhexdigest) == self.hexdigestlen
        assert self.depth > 0  # depth in theory could be zero, but then why use this?
        assert self.width > 0

    def _mktemp(self):
        """Create a named temporary file and return its filename. The
        temporary file is geneated in the hasfs root to make move()'s by
        rename instead of copy/delete.
        TODO FIX: A second uHashFS instance might return a tempfile in .files()
        """
        try:
            tmp = NamedTemporaryFile(delete=False, dir=self.tmproot,
                                     prefix='_tmp')
        except FileNotFoundError:
            os.makedirs(self.tmproot)
            tmp = NamedTemporaryFile(delete=False, dir=self.tmproot,
                                     prefix='_tmp')

        if self.fmode is not None:
            oldmask = os.umask(0)
            #try:  # why try?
            os.chmod(tmp.name, self.fmode)
            #finally:
            os.umask(oldmask)

        return tmp

    def _mvtemp(self, tmp, filepath, ts=False):
        """Move file (even if empty) to filepath on same filesystem.

        Args:
            tmp (str): Source path.  # TODO accept non-unicode filenames
            filepath (str): Destination path. Must be on same filesystem tmp.

        Returns:
            (bool): True if filepath already existed.
        """
        # if filepath does not exist, rename now
        try:
            os.link(tmp, filepath, follow_symlinks=False)
            if ts:
                print(ts)
                os.utime(filepath, ns=ts, follow_symlinks=False)
        except FileExistsError:
            os.unlink(tmp)
            return True
            # link() returned -1 EEXIST (File exists)
            # at this point a special case could be checked
            # the clde below never gets hit, leaving here to review later
            # dont need to touch the filesystem to know if filepath is empty
            # pylint: disable=W0101
            # W0101: Unreachable code (unreachable)
            if filepath.split(os.path.sep)[-1] == self.emptydigest:
                # the file on disk is zero size, otherwise it would not have
                # the emptydigest as its name, there is nothing more to do
                # since tmp is also known to be zero size by virtue of hashlib
                # generating the emptydigest from it.
                pass
            else:
                # tried replacing an assumed nonzero file
                # its gotta be nonzero because its not named the emptyhash.
                # stat() could make sure, but then we stat() every
                # pre-existing non-empty file instead of skipping atomically
                # it could be zero bytes
                # or
                # it could be != tmp's bytecount
                pass
            # pylint: enable=W0101
        except FileNotFoundError:
            os.makedirs(os.path.dirname(filepath), self.dmode)
            os.link(tmp, filepath, follow_symlinks=False)
            if ts:
                print("made dir", ts)
                os.utime(filepath, ns=ts, follow_symlinks=False)

        os.unlink(tmp)  # only if link() didnt throw exception
        return False  # file did not already exist

    def putstr(self, string):
        """Store contents of `string` on disk using its content hash for the
        address.

        Args:
            string (str): Python 3 str.

        Returns:
            HashAddress: File's hash address.
        """
        try:
            string = io.StringIO(string)
        except TypeError:
            string = io.BytesIO(string)
        return self.putstream(string)

    def putstream(self, request, progress=False):
        """Store contents of `requests.model.Request` or any object with a
        .read() method on disk using its content hash for the address.

        Args:
            stream (requests.model.Request): Readable object or path to file.

        Returns:
            HashAddress: File's hash address.
        """
        tmp = self._mktemp()
        digest = self.computehash(request, tmp, progress=progress)
        return self._commit(digest=digest, tmp=tmp)

    def putfile(self, infile, ts=True):
        """Store contents of `file` on disk using its content hash for the
        address.

        Args:
            infile (mixed): Readable object or path to file.

        Returns:
            HashAddress: File's hash address.
        """
        if ts:
            infile_stat = os.stat(infile)
            ts = (infile_stat.st_atime_ns, infile_stat.st_mtime_ns)
            assert isinstance(ts, tuple)
            assert len(ts) == 2
        if not isinstance(infile, Path):
            infile = Path(infile)
        if path_is_parent(self.root, infile):
            raise ValueError("Error: {0} exists within the hashfs"
                             "root: {1}".format(str(infile.__repr__()), self.root))  # cant just print Path's
        tmp = self._mktemp()
        try:
            digest = hash_file(infile, self.algorithm, tmp)
        except TypeError:
            digest = hash_file_handle(infile, self.algorithm, tmp)
        return self._commit(digest=digest, tmp=tmp, ts=ts)

    def _commit(self, digest, tmp, ts=False):
        #print("digest:", digest)
        assert isinstance(digest, bytes)
        #hexdigest = digest.hex()
        filepath = self.digestpath(digest)
        is_duplicate = self._mvtemp(tmp.name, filepath, ts)
        if self.redis:
            if ts:
                timestamp = ts[0]
            else:
                timestamp = time.time()
            self.redis.zadd(name=self.rediskey, mapping={digest:timestamp})
        return HashAddress(digest, self, filepath, is_duplicate)

    def gethexdigest(self, hexdigest):
        realpath = self.hexdigestpath(hexdigest)
        if os.path.isfile(realpath):
            digest = binascii.unhexlify(hexdigest)
            return HashAddress(digest, self, realpath)  # todo
        raise FileNotFoundError

    def getdigest(self, digest):
        """Return :class:`HashAdress` from given id. If `id` does not
        refer to a valid file, then ``None`` is returned.

        Args:
            digest (str): Address ID.

        Returns:
            HashAddress: File's hash address.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.digestpath(digest)
        if os.path.isfile(realpath):
            return HashAddress(digest, self, realpath)  # todo
        raise FileNotFoundError

    def opendigest(self, digest, mode='rb'):
        hexdigest = binascii.unhexlify(digest)
        return self.openhexdigest(hexdigest)

    def openhexdigest(self, hexdigest, mode='rb'):
        """Return open buffer object from given id.

        Args:
            digest (str): Address ID.
            mode (str, optional): Mode to open file in. Defaults to ``'rb'``.

        Returns:
            Buffer: An ``io`` buffer dependent on the `mode`.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.hexdigestpath(hexdigest)
        return io.open(realpath, mode)

    def deletedigest(self, digest):
        assert isinstance(digest, bytes)
        hexdigest = binascii.unhexlify(digest)
        return self.deletehexdigest(hexdigest)

    def deletehexdigest(self, hexdigest):
        """Delete file using id.

        Args:
            digest (str): Address ID.

        Returns:
           True (bool): If file was removed.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.hexdigestpath(hexdigest)
        assert realpath.startswith(str(self.root))
        os.remove(realpath)
        return True

    def files(self):
        """Return generator that yields all files in the :attr:`root`
        directory.
        """
        for folder, _, files in os.walk(self.root):
            for afile in files:
                yield os.path.abspath(os.path.join(folder, afile))

    def existsdigest(self, digest):
        """Check whether a given file digest exists on disk."""
        hexdigest = binascii.unhexlify(digest)
        return self.existshexdigest(hexdigest)

    def existshexdigest(self, hexdigest):
        """Check whether a given file digest exists on disk."""
        return os.path.isfile(self.hexdigestpath(hexdigest))

    def digestpath(self, digest):
        assert isinstance(digest, bytes)  # todo test
        hexdigest = digest.hex()
        return self.hexdigestpath(hexdigest)

    def hexdigestpath(self, hexdigest):
        """Build the file path for a given hash id.

        Args:
            digest (str): Address ID.

        Returns:
            path: An absolute file path.

        Raises:
            ValueError: If the ID is the wrong length or not hex.
        """
        if len(hexdigest) != self.hexdigestlen:
            raise ValueError('Invalid ID: "{0}" is not {1} digits '
                             'long'.format(hexdigest, self.hexdigestlen))
        try:
            int(hexdigest, 16)
        except ValueError:
            raise ValueError('Invalid ID: "{0}" '
                             'is not hex'.format(hexdigest))
        paths = self.shard(hexdigest)
        return os.path.join(self.root, self.algorithm, *paths)

    def _print_status(self, name, current_size, expected_size, end):
        if expected_size:
            print(str(int((current_size / expected_size) * 100)) + '%',
                  current_size, name, end='\r',
                  flush=True, file=sys.stderr)
        else:
            print(current_size, name, end='\r',
                  flush=True, file=sys.stderr)
        if end:
            print("", file=sys.stderr)

    def computehash(self, stream, tmp, progress=False):
        """Compute hash of file using :attr:`algorithm`."""
        hashobj = hashlib.new(self.algorithm)
        #print("type(sream):", type(stream))
        try:
            header_size = int(stream.headers['Content-Length'])
        except (KeyError, AttributeError):
            header_size = False

        for chunk in stream:
            if isinstance(chunk, str):
                chunk = bytes(chunk, 'UTF8')
            hashobj.update(chunk)
            if tmp:
                tmp.write(chunk)
                file_size = int(os.path.getsize(tmp.name))
                if progress:
                    self._print_status(name=tmp.name,
                                       current_size=file_size,
                                       expected_size=header_size, end=False)
        if tmp:
            tmp.close()
            file_size = int(os.path.getsize(tmp.name))
            if progress:
                self._print_status(name=tmp.name,
                                   current_size=file_size,
                                   expected_size=header_size, end=True)

        return hashobj.digest()

    def shard(self, digest):
        """Creates a list of `depth` number of tokens with width
        `width` from the first part of the digest plus the remainder."""
        return compact([digest[i * self.width:self.width * (i + 1)]
                        for i in range(self.depth)] + [digest])

    def corrupted(self):
        """Return generator that yields corrupted files as ``(path, address)``
        where ``path`` is the path of the corrupted file and ``address`` is
        the :class:`HashAddress` of the expected location(hash).
        """
        for path in self.files():
            digest = hash_file(path, self.algorithm, tmp=None)
            hexdigest = digest.hex()
            assert len(hexdigest) == len(path.split(os.path.sep)[-1])
            expected_path = self.hexdigestpath(hexdigest)
            if expected_path != path:
                yield (path, HashAddress(digest, self, expected_path))

    def __contains__(self, hexdigest):
        """Return whether a given digest is contained in the :attr:`root`
        directory. UGLY. Need generics. Or delete method.
        """

        return self.existshexdigest(hexdigest)

    def __iter__(self):
        """Iterate over all files in the :attr:`root` directory."""
        return self.files()


@attr.s(auto_attribs=True)
class HashAddress():
    """File address containing file's path on disk and it's content hash digest.

    Attributes:
        digest (str): Hash ID (hexdigest) of file contents.
        fs (obj): ``HashFs`` object.
        abspath (str): Absoluate path location of file on disk.
        is_duplicate (boolean, optional): Whether the hash address created was
            a duplicate of a previously existing file. Can only be ``True``
            after a put operation. Defaults to ``False``.

    """
    digest: bytes
    fs: uHashFS
    abspath: str
    is_duplicate: bool = False

    def __attrs_post_init__(self):
        #print("HashAddress digest:", self.digest)
        self.hexdigest = self.digest.hex()
