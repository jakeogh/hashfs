"""Module for HashFS class.
"""

from collections import namedtuple
from contextlib import closing
import hashlib
import io
import os
import shutil
from tempfile import NamedTemporaryFile


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
    def __init__(self,
                 root,
                 depth=4,
                 width=1,
                 algorithm='sha256',
                 fmode=0o664,
                 dmode=0o755):
        self.root = os.path.realpath(root)
        self.depth = int(depth)
        self.width = int(width)
        self.algorithm = algorithm
        self.digestlen = hashlib.new(algorithm).digest_size * 2
        self.fmode = fmode
        self.dmode = dmode

    def put(self, file):
        """Store contents of `file` on disk using its content hash for the
        address.

        Args:
            file (mixed): Readable object or path to file.

        Returns:
            HashAddress: File's hash address.
        """
        stream = Stream(file)

        with closing(stream):
            digest = self.computehash(stream)
            filepath, is_duplicate = self._copy(stream, digest)

        return HashAddress(digest, self, filepath, is_duplicate)

    def _copy(self, stream, digest):
        """Copy the contents of `stream` onto disk. The copy process uses a
        temporary file to store the initial contents and then moves that file
        to it's final location.
        """
        filepath = self.digestpath(digest)

        if not os.path.isfile(filepath):
            # Only move file if it doesn't already exist.
            is_duplicate = False
            fname = self._mktempfile(stream)
            try:
                shutil.move(fname, filepath)
            except FileNotFoundError:
                os.makedirs(os.path.dirname(filepath), self.dmode)
                shutil.move(fname, filepath)
        else:
            is_duplicate = True

        return (filepath, is_duplicate)

    def _mktempfile(self, stream):
        """Create a named temporary file from a :class:`Stream` object and
        return its filename.
        """
        tmp = NamedTemporaryFile(delete=False, dir=self.root)

        if self.fmode is not None:
            oldmask = os.umask(0)

            try:
                os.chmod(tmp.name, self.fmode)
            finally:
                os.umask(oldmask)

        for data in stream:
            if isinstance(data, str):
                data = bytes(data, 'UTF8')
            tmp.write(data)

        tmp.close()

        return tmp.name

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

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.digestpath(digest)
        assert realpath.startswith(self.root)
        os.remove(realpath)

    def files(self):
        """Return generator that yields all files in the :attr:`root`
        directory.
        """
        for folder, _, files in os.walk(self.root):
            for file in files:
                yield os.path.abspath(os.path.join(folder, file))

    def folders(self):
        """Return generator that yields all folders in the :attr:`root`
        directory that contain files.
        """
        for folder, _, files in os.walk(self.root):
            if files:
                yield folder

    def count(self):
        """Return count of the number of files in the :attr:`root` directory.
        """
        count = 0
        for _ in self:
            count += 1
        return count

    def size(self):
        """Return the total size in bytes of all files in the :attr:`root`
        directory.
        """
        total = 0
        for path in self.files():
            total += os.path.getsize(path)

        return total

    def exists(self, digest):
        """Check whether a given file digest exists on disk."""
        return os.path.isfile(self.digestpath(digest))

    def relpath(self, path):
        """Return `path` relative to the :attr:`root` directory."""
        return os.path.relpath(path, self.root)

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

    def computehash(self, stream):
        """Compute hash of file using :attr:`algorithm`."""
        hashobj = hashlib.new(self.algorithm)
        for data in stream:
            if isinstance(data, str):
                data = bytes(data, 'UTF8')
            hashobj.update(data)
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
            stream = Stream(path)

            with closing(stream):
                digest = self.computehash(stream)

            expected_path = self.digestpath(digest)

            if expected_path != path:
                yield (path, HashAddress(digest, self, expected_path))

    def __contains__(self, digest):
        """Return whether a given file digest is contained in the :attr:`root`
        directory.
        """
        return self.exists(digest)

    def __iter__(self):
        """Iterate over all files in the :attr:`root` directory."""
        return self.files()

    def __len__(self):
        """Return count of the number of files in the :attr:`root` directory.
        """
        return self.count()


class HashAddress(namedtuple('HashAddress',
                             ['id', 'fs', 'abspath', 'is_duplicate'])):
    """File address containing file's path on disk and it's content hash ID.

    Attributes:
        digest (str): Hash ID (hexdigest) of file contents.
        fs (obj): ``HashFs`` object.
        abspath (str): Absoluate path location of file on disk.
        is_duplicate (boolean, optional): Whether the hash address created was
            a duplicate of a previously existing file. Can only be ``True``
            after a put operation. Defaults to ``False``.
    """
    def __new__(cls, digest, fs, abspath, is_duplicate=False):
        return super(HashAddress, cls).__new__(cls,
                                               digest,
                                               fs,
                                               abspath,
                                               is_duplicate)

    def __init__(self, digest, fs, abspath, is_duplicate=False):
        self.relpath = fs.relpath(self.abspath)


class Stream():
    """Common interface for file-like objects.

    The input `obj` can be a file-like object or a path to a file. If `obj` is
    a path to a file, then it will be opened until :meth:`close` is called.
    If `obj` is a file-like object, then it's original position will be
    restored when :meth:`close` is called instead of closing the object
    automatically. Closing of the stream is deferred to whatever process passed
    the stream in.

    Successive readings of the stream is supported without having to manually
    set it's position back to ``0``.
    """
    def __init__(self, obj):
        if hasattr(obj, 'read'):
            pos = obj.tell()
        elif os.path.isfile(obj):
            obj = io.open(obj, 'rb')
            pos = None
        else:
            raise ValueError(('Object must be a valid file path or '
                              'a readable object.'))
        self._obj = obj
        self._pos = pos

    def __iter__(self):
        """Read underlying IO object and yield results. Return object to
        original position if we didn't open it originally.
        """
        self._obj.seek(0)

        while True:
            data = self._obj.read()
            if not data:
                break
            yield data

        if self._pos is not None:
            self._obj.seek(self._pos)

    def close(self):
        """Close underlying IO object if we opened it, else return it to
        original position.
        """
        if self._pos is None:
            self._obj.close()
        else:
            self._obj.seek(self._pos)
