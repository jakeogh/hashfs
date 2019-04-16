"""Module for HashFS class.
"""

import pathlib
import hashlib
import io
import os
import shutil
from tempfile import NamedTemporaryFile
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


def hash_file(path, algorithm, tmp=None):
    block_size = 256 * 128 * 2
    hasher = hashlib.new(algorithm)
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(block_size), b''):
            hasher.update(chunk)
            if tmp:
                tmp.write(chunk)
        if tmp:
            tmp.close()
    return hasher.hexdigest()


def hash_file_handle(handle, algorithm, tmp=None):
    block_size = 256 * 128 * 2
    hasher = hashlib.new(algorithm)
    pos = handle.tell()
    for chunk in iter(lambda: handle.read(block_size), b''):
        hasher.update(chunk)
        if tmp:
            tmp.write(chunk)
    if tmp:
        tmp.close()

    handle.seek(pos)
    return hasher.hexdigest()


@attr.s(auto_attribs=True)
class HashFS():
    """Content addressable file manager.

    Attributes:
        root (str): Directory path used as root of storage space.
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
    root: str = attr.ib(converter=pathlib.Path)
    depth: int = 3
    width: int = 1
    algorithm: str = 'sha256'
    fmode: int = 0o664
    dmode: int = 0o755

    def __attrs_post_init__(self):
        self.root = self.root.resolve()
        self.digestlen = hashlib.new(self.algorithm).digest_size * 2
        assert self.depth > 0
        assert self.width > 0

    def _mktemp(self):
        """Create a named temporary file and return its filename. The
        temporary file is geneated in the hasfs root to make move()'s by
        rename instead of copy/delete.
        TODO FIX: A second HashFS instance might return a tempfile in .files()
        """
        try:
            tmp = NamedTemporaryFile(delete=False, dir=self.root)
        except FileNotFoundError:
            os.makedirs(self.root)
            tmp = NamedTemporaryFile(delete=False, dir=self.root)

        if self.fmode is not None:
            oldmask = os.umask(0)
            try:
                os.chmod(tmp.name, self.fmode)
            finally:
                os.umask(oldmask)

        return tmp

    def _mvtemp(self, tmp, filepath):
        if not os.path.isfile(filepath):
            # Only move file if it doesn't already exist.
            is_duplicate = False
            assert os.path.getsize(tmp.name) > 0
            try:
                shutil.move(tmp.name, filepath)
            except FileNotFoundError:
                os.makedirs(os.path.dirname(filepath), self.dmode)
                shutil.move(tmp.name, filepath)
        else:
            is_duplicate = True
            tmp_size = os.path.getsize(tmp.name)
            existing_size = os.path.getsize(filepath)
            assert tmp_size == existing_size

        return is_duplicate

    def putstr(self, string):
        """Store contents of `string` on disk using its content hash for the
        address.

        Args:
            string (str): Python 3 str.

        Returns:
            HashAddress: File's hash address.
        """
        string = io.StringIO(string)
        tmp = self._mktemp()
        digest = self.computehash(string, tmp)
        filepath = self.digestpath(digest)
        is_duplicate = self._mvtemp(tmp, filepath)

        return HashAddress(digest, self, filepath, is_duplicate)

    def putrequest(self, request):
        """Store contents of `requests.model.Request` on disk using its
        content hash for the address.

        Args:
            stream (requests.model.Request): Readable object or path to file.

        Returns:
            HashAddress: File's hash address.
        """
        tmp = self._mktemp()
        digest = self.computehash(request, tmp)
        filepath = self.digestpath(digest)
        is_duplicate = self._mvtemp(tmp, filepath)

        return HashAddress(digest, self, filepath, is_duplicate)

    def putfile(self, file):
        """Store contents of `file` on disk using its content hash for the
        address.

        Args:
            file (mixed): Readable object or path to file.

        Returns:
            HashAddress: File's hash address.
        """
        tmp = self._mktemp()
        try:
            digest = hash_file(file, self.algorithm, tmp)
        except TypeError:
            digest = hash_file_handle(file, self.algorithm, tmp)

        filepath = self.digestpath(digest)
        is_duplicate = self._mvtemp(tmp, filepath)

        return HashAddress(digest, self, filepath, is_duplicate)

    def get(self, digest):
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

    def open(self, digest, mode='rb'):
        """Return open buffer object from given id.

        Args:
            digest (str): Address ID.
            mode (str, optional): Mode to open file in. Defaults to ``'rb'``.

        Returns:
            Buffer: An ``io`` buffer dependent on the `mode`.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.digestpath(digest)
        return io.open(realpath, mode)

    def delete(self, digest):
        """Delete file using id.

        Args:
            digest (str): Address ID.

        Returns:
           True (bool): If file was removed.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.digestpath(digest)
        assert realpath.startswith(str(self.root))
        os.remove(realpath)
        return True

    def files(self):
        """Return generator that yields all files in the :attr:`root`
        directory.
        """
        for folder, _, files in os.walk(self.root):
            for file in files:
                yield os.path.abspath(os.path.join(folder, file))

    def exists(self, digest):
        """Check whether a given file digest exists on disk."""
        return os.path.isfile(self.digestpath(digest))

    def digestpath(self, digest):
        """Build the file path for a given hash id.

        Args:
            digest (str): Address ID.

        Returns:
            path: An absolute file path.

        Raises:
            ValueError: If the ID is the wrong length or not hex.
        """
        if len(digest) != self.digestlen:
            raise ValueError('Invalid ID: "{0}" is not {1} digits '
                             'long'.format(digest, self.digestlen))
        try:
            int(digest, 16)
        except ValueError:
            raise ValueError('Invalid ID: "{0}" '
                             'is not hex'.format(digest))
        paths = self.shard(digest)
        return os.path.join(self.root, *paths)

    def computehash(self, stream, tmp):
        """Compute hash of file using :attr:`algorithm`."""
        hashobj = hashlib.new(self.algorithm)
        for chunk in stream:
            if isinstance(chunk, str):
                chunk = bytes(chunk, 'UTF8')
            hashobj.update(chunk)
            if tmp:
                tmp.write(chunk)
        if tmp:
            tmp.close()
        return hashobj.hexdigest()

    def shard(self, digest):
        """Creates a list of `depth` number of tokens with width
        `width` from the first part of the digest plus the remainder."""
        return compact([digest[i * self.width:self.width * (i + 1)]
                        for i in range(self.depth)] + [digest])

    def corrupted(self):
        """Return generator that yields corrupted files as ``(path, address)``
        where ``path`` is the path of the corrupted file and ``address`` is
        the :class:`HashAddress` of the expected location.
        """
        for path in self.files():
            digest = hash_file(path, self.algorithm)
            assert len(digest) == len(path.split(os.path.sep)[-1])
            expected_path = self.digestpath(digest)
            if expected_path != path:
                yield (path, HashAddress(digest, self, expected_path))

    def __contains__(self, digest):
        """Return whether a given digest is contained in the :attr:`root`
        directory.
        """
        return self.exists(digest)

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
    digest: str
    fs: HashFS
    abspath: str
    is_duplicate: bool = False
