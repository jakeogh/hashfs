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


def issubdir(subpath, path):
    """Return whether `subpath` is a sub-directory of `path`."""
    # Append os.sep so that paths like /usr/var2/log doesn't match /usr/var.
    path = os.path.realpath(path) + os.sep
    subpath = os.path.realpath(subpath)
    return subpath.startswith(path)


class HashFS(object):
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
            id = self.computehash(stream)
            filepath, is_duplicate = self._copy(stream, id)

        return HashAddress(id, self, filepath, is_duplicate)

    def _copy(self, stream, id):
        """Copy the contents of `stream` onto disk. The copy process uses a
        temporary file to store the initial contents and then moves that file
        to it's final location.
        """
        filepath = self.idpath(id)

        if not os.path.isfile(filepath):
            # Only move file if it doesn't already exist.
            is_duplicate = False
            fname = self._mktempfile(stream)
            try:
                shutil.move(fname, filepath)
            except FileNotFoundError:
                self.makepath(os.path.dirname(filepath))
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

    def get(self, id):
        """Return :class:`HashAdress` from given id. If `id` does not
        refer to a valid file, then ``None`` is returned.

        Args:
            id (str): Address ID.

        Returns:
            HashAddress: File's hash address.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.idpath(id)
        if os.path.isfile(realpath):
            return HashAddress(id, self, realpath)  # todo
        else:
            raise FileNotFoundError

    def open(self, id, mode='rb'):
        """Return open buffer object from given id.

        Args:
            id (str): Address ID.
            mode (str, optional): Mode to open file in. Defaults to ``'rb'``.

        Returns:
            Buffer: An ``io`` buffer dependent on the `mode`.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.idpath(id)
        return io.open(realpath, mode)

    def delete(self, id):
        """Delete file using id. Remove any empty directories after deleting.

        Args:
            id (str): Address ID.

        Raises:
            FileNotFoundError: If file doesn't exist.
        """
        realpath = self.idpath(id)
        assert realpath.startswith(self.root)
        os.remove(realpath)
        self.remove_empty(os.path.dirname(realpath))

    def remove_empty(self, subpath):
        """Successively remove all empty folders starting with `subpath` and
        proceeding "up" through directory tree until reaching the :attr:`root`
        folder.
        """
        # Don't attempt to remove any folders if subpath is not a
        # subdirectory of the root directory.
        if not self.haspath(subpath):
            return

        while subpath != self.root:
            if os.listdir(subpath) or os.path.islink(subpath):
                break
            os.rmdir(subpath)
            subpath = os.path.dirname(subpath)

    def files(self):
        """Return generator that yields all files in the :attr:`root`
        directory.
        """
        for folder, subfolders, files in os.walk(self.root):
            for file in files:
                yield os.path.abspath(os.path.join(folder, file))

    def folders(self):
        """Return generator that yields all folders in the :attr:`root`
        directory that contain files.
        """
        for folder, subfolders, files in os.walk(self.root):
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

    def exists(self, id):
        """Check whether a given file id exists on disk."""
        return os.path.isfile(self.idpath(id))

    def haspath(self, path):
        """Return whether `path` is a subdirectory of the :attr:`root`
        directory.
        """
        return issubdir(path, self.root)

    def makepath(self, path):
        """Physically create the folder path on disk."""
        os.makedirs(path, self.dmode)

    def relpath(self, path):
        """Return `path` relative to the :attr:`root` directory."""
        return os.path.relpath(path, self.root)

    def idpath(self, id):
        """Build the file path for a given hash id.

        Args:
            id (str): Address ID.

        Returns:
            path: An absolute file path.

        Raises:
            ValueError: If the ID is the wrong length or not hex.
        """
        if len(id) != self.digestlen:
            raise ValueError('Invalid ID: "{0}" is not {1} digits '
                             'long'.format(id, self.digestlen))
        try:
            int(id, 16)
        except ValueError:
            raise ValueError('Invalid ID: "{0}" '
                             'is not hex'.format(id))
        paths = self.shard(id)
        return os.path.join(self.root, *paths)

    def computehash(self, stream):
        """Compute hash of file using :attr:`algorithm`."""
        hashobj = hashlib.new(self.algorithm)
        for data in stream:
            # hashobj.update(to_bytes(data))
            if isinstance(data, str):
                data = bytes(data, 'UTF8')
            hashobj.update(data)
        return hashobj.hexdigest()

    def shard(self, id):
        """Creates a list of `depth` number of tokens with width
        `width` from the first part of the id plus the remainder."""
        return compact([id[i * self.width:self.width * (i + 1)]
                        for i in range(self.depth)] + [id])

    def unshard(self, path):
        """Unshard path to determine hash value."""
        if not self.haspath(path):
            raise ValueError(('Cannot unshard path. The path "{0}" is not '
                              'a subdirectory of the root directory "{1}"'
                              .format(path, self.root)))

        return path.split(os.sep)[-1]

    def corrupted(self):
        """Return generator that yields corrupted files as ``(path, address)``
        where ``path`` is the path of the corrupted file and ``address`` is
        the :class:`HashAddress` of the expected location.
        """
        for path in self.files():
            stream = Stream(path)

            with closing(stream):
                id = self.computehash(stream)

            expected_path = self.idpath(id)

            if expected_path != path:
                yield (path, HashAddress(id, self, expected_path))

    def __contains__(self, id):
        """Return whether a given file id is contained in the :attr:`root`
        directory.
        """
        return self.exists(id)

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
        id (str): Hash ID (hexdigest) of file contents.
        fs (obj): ``HashFs`` object.
        abspath (str): Absoluate path location of file on disk.
        is_duplicate (boolean, optional): Whether the hash address created was
            a duplicate of a previously existing file. Can only be ``True``
            after a put operation. Defaults to ``False``.
    """
    def __new__(cls, id, fs, abspath, is_duplicate=False):
        return super(HashAddress, cls).__new__(cls,
                                               id,
                                               fs,
                                               abspath,
                                               is_duplicate)

    def __init__(self, id, fs, abspath, is_duplicate=False):
        self.relpath = fs.relpath(self.abspath)


class Stream(object):
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
