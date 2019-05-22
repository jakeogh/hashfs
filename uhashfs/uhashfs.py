"""Module for uHashFS class."""

from math import inf
from pathlib import Path
import hashlib
import io
import os
import sys
import time
import random
from itertools import product
from tempfile import NamedTemporaryFile
import binascii
import redis
import attr
import numpy
from kcl.printops import ceprint
from kcl.printops import eprint
from kcl.symlinkops import create_relative_symlink

#import IPython
#IPython.embed()


def really_is_file(path):
    assert isinstance(path, Path)
    if path.is_symlink():
        return False
    if path.is_file(): # is_file() answers True for symlinks (unless they are broken) and crashes with an OSError on self-symlinks
        return True
    return False


def really_is_dir(path):
    assert isinstance(path, Path)
    if path.is_symlink():
        return False
    if path.is_dir(): # is_dir() answers False for broken symlinks, and crashes with an OSError on self-symlinks
        return True
    return False


@attr.s(auto_attribs=True, kw_only=True)
class Path_Iterator():
    path: str = attr.ib(converter=Path)
    min_depth: int = 1
    max_depth: object = inf
    follow_symlinks: bool = False
    return_dirs: bool = True
    return_files: bool = True
    return_symlinks: bool = True

    def __attrs_post_init__(self):
        self.root = self.path
        if self.follow_symlinks:
            assert not self.return_symlinks  # todo broken symlinks

    def go(s):
        depth = len(s.path.parts) - len(s.root.parts)  # len('/') == 1
        if depth >= s.min_depth:
            if s.return_dirs and s.path.is_dir():
                if depth <= s.max_depth:
                    yield s.path.absolute()
            if s.return_files and not s.path.is_dir():  # dir/fifo/file/symlink/socket/reserved/char/block/bla/bla
                if depth <= s.max_depth:
                    yield s.path.absolute()

        if depth > s.max_depth:
            return
        for sub in s.path.iterdir():
            depth = len(sub.parts) - len(s.root.parts)
            if depth > s.max_depth:
                return
            if sub.is_symlink():  # must be before is_dir() # bug didnt check follow_symlinks
                if s.return_files:
                    yield sub.absolute()
            elif sub.is_dir():
                #print("could yield dir:", sub)
                s.path = sub
                yield from s.go()
            else:
                if s.return_files:
                    yield sub.absolute()


def compact(items):
    return [item for item in items if item]


def unshard(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('Path must be absolute.')  # not really, but less chance for other bugs
    return path.name


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
    parent = parent.expanduser().resolve()
    child = child.expanduser().resolve()
    return os.path.commonpath([parent]) == os.path.commonpath([parent, child])


def get_mtime(infile):
    try:
        infile_stat = os.stat(infile)
    except TypeError:
        infile_stat = os.stat(infile.fileno())
    mtime = (infile_stat.st_atime_ns, infile_stat.st_mtime_ns)
    return mtime


@attr.s(auto_attribs=True, kw_only=True)
class uHashFSBase():
    root: str = attr.ib(converter=Path)
    depth: int = 4
    width: int = 1
    algorithm: str = 'sha3_256'
    fmode: int = 0o444
    dmode: int = 0o755
    verbose: bool = False
    redis: bool = False
    legacy: bool = False

    def __attrs_post_init__(self):
        self.root = self.root.resolve()
        self.tmp = "_tmp"  # needed only by uHashFS but required here to make sure it does not collide
        assert self.algorithm != self.tmp
        self.digestlen = hashlib.new(self.algorithm).digest_size
        self.hexdigestlen = self.digestlen * 2
        self.emptydigest = getattr(hashlib, self.algorithm)(b'').digest()
        # this record could get created when _tmp is created.... it would id a hash tree independent of it's hash folder name
        # it would also be a way to check the depth and width of a unknown, pre-existing fs in the check()
        self.emptyhexdigest = self.emptydigest.hex()
        assert len(self.emptydigest) == self.digestlen
        assert len(self.emptyhexdigest) == self.hexdigestlen
        assert self.depth > 0  # depth in theory could be zero, but then why use this?
        assert self.width > 0
        self.ns = set(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'])  # dont make generator or can only be called once
        self.ns_width = set([''.join(comb) for comb in product(self.ns, repeat=self.width)])  # ditto
        self.edge_count = len(self.ns_width) ** self.depth
        if self.redis:
            self.redis = redis.StrictRedis(host='127.0.0.1')
            app_name = type(self).__module__ + '.' + type(self).__name__
            self.rediskey = ':'.join([app_name, str(self.root), self.algorithm]) + '#'
            if not self.redis.exists(self.rediskey):
                self._commit_redis(digest=self.emptydigest, filepath=None)  # fix if decide to make emptyhash
            if self.verbose:
                print("self.rediskey:", self.rediskey, file=sys.stderr)

    def _commit_redis(self, digest, filepath):
        if filepath:
            mtime = get_mtime(filepath)
        else:
            assert digest == self.emptydigest
            mtime = str(time.time())
        self.redis.zadd(name=self.rediskey, mapping={digest: mtime})

    def shard(self, hexdigest):
        return compact([hexdigest[i * self.width:self.width * (i + 1)]
                        for i in range(self.depth)] + [hexdigest])

    def hexdigestpath(self, hexdigest):
        if len(hexdigest) != self.hexdigestlen:
            raise ValueError('Invalid ID: "{0}" is not {1} digits long'.format(hexdigest, self.hexdigestlen))
        try:
            int(hexdigest, 16)
        except ValueError:
            raise ValueError('Invalid ID: "{0}" is not hex'.format(hexdigest))
        paths = self.shard(hexdigest)
        rel_path = Path(os.path.join(*paths))

        if self.legacy:
            hash_folder_path = self.root / Path(self.algorithm)
            assert not hash_folder_path.exists()  # dont accidently write to a non-legacy uhashfs
            path = Path(os.path.join(self.root, *paths))
        else:
            path = self.root / Path(self.algorithm) / rel_path

        return path

    def paths(self, **kwargs):
        fiterator = Path_Iterator(**kwargs).go()
        for thing in fiterator:
            yield thing

    def files(self):
        fiterator = self.paths(path=self.root, return_dirs=False, return_symlinks=False)
        return fiterator

    def edges(self):
        ns_depth = (''.join(comb) for comb in product(self.ns_width, repeat=self.depth))
        leaf_paths = ('/'.join(list(comb)) for comb in ns_depth)
        return leaf_paths

    def random_edge_folder(self):
        random_edge = random.sample(self.ns_width, self.depth)
        random_edge = os.path.join(*random_edge)
        if self.legacy:
            path = self.root / Path(random_edge)
        else:
            path = self.root / Path(self.algorithm) / Path(random_edge)
        return path

    def estimate_edge_properites(self, variance):
        assert variance >= 0
        cnf = 100
        samples = []
        samples_total_bytes = []
        while cnf > variance:
            sample_total_bytes = 0
            random_edge_folder = self.random_edge_folder()
            try:
                sample = list(self.paths(path=random_edge_folder))
                for thing in sample:
                    sample_total_bytes += os.stat(thing).st_size
                sample = len(sample)
            except FileNotFoundError:
                sample = 0  # valid and true

            if self.verbose:
                print("random_edge_folder:", random_edge_folder, file=sys.stderr)
                print("sample:", sample, file=sys.stderr)
                print("sample_total_bytes:", sample_total_bytes, file=sys.stderr)
            samples.append(sample)
            samples_total_bytes.append(sample_total_bytes)
            if len(samples) > 2:
                pmean = numpy.mean(samples[:-1])
                mean = numpy.mean(samples)
                cnf = abs(pmean - mean)
                if self.verbose:
                    print("cnf:", cnf, file=sys.stderr)
        return (int(mean), numpy.mean(samples_total_bytes))  # ugly

    def estimate_tree_properites(self, variance):
        object_count_per_edge, bytes_per_edge = self.estimate_edge_properites(variance=variance)
        if self.verbose:
            print("object_count_per_edge:", object_count_per_edge, file=sys.stderr)
            print("bytes_per_edge:", bytes_per_edge, file=sys.stderr)
            print("self.edge_count:", self.edge_count, file=sys.stderr)
        object_count_estimate = self.edge_count * object_count_per_edge
        byte_count_estimate = self.edge_count * bytes_per_edge
        return (int(object_count_estimate), byte_count_estimate)

    #def estimate_edge_folder_size(self, variance):
    #    _, edge_size_estimate = estimate_object_count_and_total_size_per_edge(variance)
    #    return

    def check(self, skip_cached=False, quiet=False):  # todo verify perms and attrs
        #import IPython
        #IPython.embed()
        longest_path = 0
        for path in self.paths(path=self.root, return_symlinks=False, return_dirs=True):
            pathlen = len(path.absolute().as_posix())
            longest_path = max(longest_path, pathlen)
            pad = longest_path - pathlen
            pad = pad * ' ' + '\r'
            if not self.verbose:
                if not quiet:
                    print(path, end=pad, file=sys.stderr, flush=True)
            assert path_is_parent(self.root, path)
            rel_root = path.relative_to(self.root)
            if self.verbose:
                eprint("path:", path)
                eprint("rel_root:", rel_root)
            if not self.legacy:
                assert rel_root.parts[0] in (self.algorithm, '_tmp')
            if really_is_file(path):
                if hasattr(self, "tmproot"):
                    if self.redis and skip_cached:
                        if self.redis.zscore(self.rediskey, binascii.unhexlify(path.name)):
                            if self.verbose:
                                print("skipped hashing:", path)
                            continue

                    digest = hash_file(path, self.algorithm, tmp=None)
                    hexdigest = digest.hex()
                    try:
                        assert len(hexdigest) == len(path.name)
                    except AssertionError as e:
                        eprint("path:", path)
                        raise e
                    expected_path = self.hexdigestpath(hexdigest)
                    if expected_path != path:
                        yield (path, HashAddress(digest, self, expected_path))
                    else:
                        if self.redis:
                            self._commit_redis(digest, filepath=path)
                else:
                    assert path.lstat().st_size == 0
            elif really_is_dir(path):
                try:
                    if hasattr(self, "tmproot"):
                        assert (len(rel_root.parts) - 1) <= self.depth
                    if rel_root == Path(self.tmp):
                        continue
                    if self.legacy:
                        tree_path = rel_root
                    else:
                        tree_path = rel_root.relative_to(self.algorithm)
                    if tree_path.name:
                        if len(tree_path.parts) <= self.depth:
                            assert len(tree_path.name) == self.width
                            assert tree_path.name in self.ns  # bug for angryfiles to find
                        elif len(tree_path.parts) == self.depth + 1:
                            assert len(tree_path.name) == self.hexdigestlen
                            try:
                                assert tree_path.parts[0:-1] == self.shard(tree_path.name)
                            except AssertionError as e:
                                print(e)
                                import IPython
                                IPython.embed()
                                #raise e
                        elif len(tree_path.parts) == self.depth + 2:
                            assert tree_path.name in ('archive', 'tags', 'strings')
                        elif len(tree_path.parts) == self.depth + 3:
                            assert float(tree_path.name)
                        elif len(tree_path.parts) == self.depth + 4:
                            assert tree_path.name in ('021_requests.plugin')
                        else:
                            assert False
                except AssertionError as e:
                    print("\n", path)
                    raise e


@attr.s(auto_attribs=True, kw_only=True)
class uHashFSMetadata(uHashFSBase):
    uhashfs: object

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        assert isinstance(self.uhashfs, uHashFS)

    def putrecord(self, about_hash: object, to_hash: object, link_name: str, data_source_name: str, timestamp: str):
        assert isinstance(about_hash, HashAddress)
        assert isinstance(to_hash, HashAddress)
        assert isinstance(link_name, str)
        dest_about = self.root / about_hash.relative_path
        dest_archive = dest_about / Path("archive") / Path(timestamp)  # todo generalize
        dest = dest_archive / Path(data_source_name)
        try:
            try:
                os.symlink(to_hash.hexdigest, dest / Path(link_name))
            except FileNotFoundError:
                os.makedirs(dest)
                os.symlink(to_hash.hexdigest, dest / Path(link_name))
        except FileNotFoundError as e:  # I dont really want to, but python wants an except here
            raise e
        else:  # only do this stuff if the inner try/except did not throw an exception out
            try:
                os.unlink(dest_about / Path("latest_archive"))
            except FileNotFoundError:
                pass
            try:
                create_relative_symlink(dest_archive, dest_about / Path("latest_archive"))
            except FileExistsError:
                # another process won the race
                pass


@attr.s(auto_attribs=True, kw_only=True)
class uHashFS(uHashFSBase):
    """Content addressable file manager.

    Attributes:
        root (str): Directory path used as root of storage space.
        tmproot (str): Optional directory used for NamedTemporaryFile storage
            space. Defaults to the hashfs root. Must be on the same filesystem.
        depth (int, optional): Depth of subfolders to create when saving a file.
        width (int, optional): Width of each subfolder to create when saving a file.
        algorithm (str): Hash algorithm to use when computing file hash.
            Algorithm should be available in ``hashlib`` module.
        fmode (int, optional): File mode permission to set when adding files to a directory.
        dmode (int, optional): Directory mode permission to set for subdirectories.
    """

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        self.tmproot = self.root / Path(self.tmp)

    def _mktemp(self):
        try:
            tmp = NamedTemporaryFile(delete=False, dir=self.tmproot, prefix='_tmp')
        except FileNotFoundError:
            os.makedirs(self.tmproot)
            tmp = NamedTemporaryFile(delete=False, dir=self.tmproot, prefix='_tmp')

        if self.fmode is not None:
            oldmask = os.umask(0)
            os.chmod(tmp.name, self.fmode)
            os.umask(oldmask)

        return tmp

    def _mvtemp(self, tmp, filepath, mtime=False):  # todo add test for mtime=False
        '''returns True if file existed, False if new'''
        # if filepath does not exist, rename now
        try:
            os.link(tmp, filepath, follow_symlinks=False)
            if mtime:
                os.utime(filepath, ns=mtime, follow_symlinks=False)  # purpose fail if this throws an exception
        except FileExistsError:
            os.unlink(tmp)
            return True
            # link() returned -1 EEXIST (File exists)
            # at this point a special case could be checked
            # the code below never gets hit, leaving here to review later
            # dont need to touch the filesystem to know if filepath is empty
            # pylint: disable=W0101
            # W0101: Unreachable code (unreachable)
            if filepath.name == self.emptydigest:
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
            try:
                os.makedirs(os.path.dirname(filepath), self.dmode)
            except FileExistsError:  # another process won the mkdir race
                assert really_is_dir(os.path.dirname(filepath))  # rare, no harm checking assumptions

            try:
                os.link(tmp, filepath, follow_symlinks=False)  # rare, another process could win this race too
                if mtime:
                    os.utime(filepath, ns=mtime, follow_symlinks=False)  # purpose fail if this throws an exception
            except FileExistsError:
                pass  # could verify hash, but cant think of a reason it could be more likely wrong (due to this code) other than those covered by check()

        os.unlink(tmp)  # only if link() didnt throw exception, it should not be possible for this to throw an exception due to a race by virtue of tmp file uniqueness per-process
        return False  # file did not already exist

    def putstr(self, string):
        try:
            string = io.StringIO(string)
        except TypeError:
            string = io.BytesIO(string)
        return self.putstream(string)

    def putstream(self, request, progress=False):
        tmp = self._mktemp()
        digest = self.computehash(request, tmp, progress=progress)
        return self._commit(digest=digest, tmp=tmp)

    def putfile(self, infile, preserve_mtime=True):
        if preserve_mtime:
            mtime = get_mtime(infile)
        else:
            mtime = False

        if not isinstance(infile, Path):
            try:
                infile = Path(infile)
            except TypeError:   # _io.BufferedReader
                infile = Path(infile.name)
        if path_is_parent(self.root, infile):
            raise ValueError("Error: {0} exists within the hashfs"
                             "root: {1}".format(str(infile.__repr__()), self.root))  # cant just print Path's
        tmp = self._mktemp()
        try:
            digest = hash_file(infile, self.algorithm, tmp)
        except TypeError:
            digest = hash_file_handle(infile, self.algorithm, tmp)  # bug, could get passed False and "work"
        return self._commit(digest=digest, tmp=tmp, mtime=mtime)

    def _commit(self, digest, tmp, mtime=False):
        assert isinstance(digest, bytes)
        filepath = self.digestpath(digest)
        is_duplicate = self._mvtemp(tmp.name, filepath, mtime)
        if self.redis:
            self._commit_redis(digest=digest, filepath=filepath)
        return HashAddress(digest, self, filepath, is_duplicate)

    def gethexdigest(self, hexdigest):
        realpath = self.hexdigestpath(hexdigest)
        digest = binascii.unhexlify(hexdigest)

        if self.redis:
            if self.redis.zscore(self.rediskey, digest):
                if self.verbose:
                    eprint("got cached digest from redis:", self.rediskey, hexdigest)
                return HashAddress(digest, self, realpath)

            # shouldnt be added unless it's had it's on-disk hash verified?
            #if really_is_file(realpath):
            #    self.redis.sadd(self.rediskey, digest)
            #    return HashAddress(digest, self, realpath)
            #raise FileNotFoundError

        if really_is_file(realpath):
            return HashAddress(digest, self, realpath)  # todo
        raise FileNotFoundError

    def getdigest(self, digest):
        realpath = self.digestpath(digest)
        if self.redis:
            if self.redis.zscore(self.rediskey, digest):
                if self.verbose:
                    eprint("got cached digest from redis:", self.rediskey, digest.hex())
                return HashAddress(digest, self, realpath)

            #if really_is_file(realpath):
            #    self.redis.sadd(self.rediskey, digest)
            #    return HashAddress(digest, self, realpath)
            #raise FileNotFoundError

        if really_is_file(realpath):
            return HashAddress(digest, self, realpath)  # todo
        raise FileNotFoundError

    def opendigest(self, digest, mode='rb'):
        hexdigest = binascii.unhexlify(digest)
        return self.openhexdigest(hexdigest)

    def openhexdigest(self, hexdigest, mode='rb'):
        realpath = self.hexdigestpath(hexdigest)
        return io.open(realpath, mode)

    def deletedigest(self, digest):
        assert isinstance(digest, bytes)
        hexdigest = binascii.unhexlify(digest)
        return self.deletehexdigest(hexdigest)

    def deletehexdigest(self, hexdigest):
        realpath = self.hexdigestpath(hexdigest)
        assert path_is_parent(self.root, realpath)
        assert hexdigest != self.emptyhexdigest  # used for depth, width and algorithm auto-detection
        os.remove(realpath)
        if self.redis:
            digest = binascii.unhexlify(hexdigest)
            self.redis.srem(self.rediskey, digest)
        return True

    def existsdigest(self, digest):
        if self.redis:
            if self.redis.zscore(self.rediskey, digest):
                return True
            #return False  # hm, assume redis is consistent?
        hexdigest = binascii.unhexlify(digest)
        return self.existshexdigest(hexdigest)

    def existshexdigest(self, hexdigest):
        if self.redis:
            digest = binascii.unhexlify(hexdigest)
            if self.redis.zscore(self.rediskey, digest):
                return True
            #return False  # hm, assume redis is consistent?
        hexdigestpath = self.hexdigestpath(hexdigest)
        return really_is_file(hexdigestpath)

    def digestpath(self, digest):
        assert isinstance(digest, bytes)  # todo test
        hexdigest = digest.hex()
        return self.hexdigestpath(hexdigest)

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
        hashobj = hashlib.new(self.algorithm)
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

    def __contains__(self, hexdigest):
        return self.existshexdigest(hexdigest)

    def __iter__(self):
        return self.files()


@attr.s(auto_attribs=True)
class HashAddress():  # todo, let open() call this
    digest: bytes
    fs: uHashFS
    abspath: str = attr.ib(converter=Path)
    is_duplicate: bool = False

    def __attrs_post_init__(self):
        #self.abspath.resolve()  # todo, see if this stat()'s
        self.hexdigest = self.digest.hex()
        self.relative_path = self.abspath.relative_to(self.fs.root)
