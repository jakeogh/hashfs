# -*- coding: utf-8 -*-

import time
from io import BufferedReader
import os
import py
import pytest
from uhashfs import uHashFS, unshard, path_is_parent

TIMESTAMP = str(time.time())


@pytest.fixture
def testpath_outside_fsroot(tmpdir):
    return tmpdir.mkdir('uhashfs_input_files_' + TIMESTAMP)


@pytest.fixture
def testpath_fsroot(tmpdir):
    return tmpdir.mkdir('uhashfs_root' + TIMESTAMP)


@pytest.fixture
def fs_relative():
    return uHashFS(root='relative_path' + TIMESTAMP, algorithm='sha3_256', width=1, depth=4)


@pytest.fixture
def testfile_outside_fsroot(testpath_outside_fsroot):
    return testpath_outside_fsroot.join('uhashfs.txt')


@pytest.fixture
def testfile_fsroot(testpath_fsroot):
    return testpath_fsroot.join('uhashfs.txt')


@pytest.yield_fixture
def fileio_outside_fsroot(testfile_outside_fsroot):
    with open(str(testfile_outside_fsroot), 'wb') as io:
        io.write(b'foo')

    io = open(str(testfile_outside_fsroot), 'rb')
    yield io
    io.close()


@pytest.yield_fixture
def fileio_fsroot(testfile_fsroot):
    with open(str(testfile_fsroot), 'wb') as io:
        io.write(b'foo')

    io = open(str(testfile_fsroot), 'rb')
    #import IPython
    #IPython.embed()
    yield io
    io.close()


@pytest.fixture
def unicodestring():
    return 'foo'


@pytest.fixture
def all_bytes():
    return set([bytes(chr(x), encoding='Latin-1') for x in range(0, 256)])


@pytest.fixture
def filepath_outside_fsroot(testfile_outside_fsroot):
    testfile_outside_fsroot.write(b'foo')
    return testfile_outside_fsroot


@pytest.fixture
def filepath_fsroot(testfile_fsroot):
    testfile_fsroot.write(b'foo')
    return testfile_fsroot


@pytest.fixture
def fs(testpath_fsroot):
    return uHashFS(root=str(testpath_fsroot), algorithm='sha3_256', width=1, depth=4)


@pytest.fixture
def fssha1(testpath_fsroot):
    return uHashFS(root=str(testpath_fsroot), algorithm='sha1', width=1, depth=4)


def putstr_range(fs, count):
    return dict((address.abspath, address)
                for address in (fs.putstr(u'{0}'.format(i))
                                for i in range(count)))


def assert_file_put(fs, address):
    directory = os.path.dirname(address.abspath)
    reldirectory = str(directory).split(str(fs.root))[-1]
    dir_parts = [part for part in reldirectory.split(os.path.sep) if part]

    assert address.abspath in tuple(py.path.local(fs.root).visit())
    assert fs.existshexdigest(address.hexdigest)

    hexdigest = str(address.abspath).split(os.path.sep)[-1]
    assert hexdigest == address.hexdigest

    assert (len(dir_parts) - 1) == fs.depth
    assert all(len(part) == fs.width for part in dir_parts[1:])
    # assert len(list(fs.files())) == 1


def test_uhashfs_put_fileobj_from_inside_root(fs, fileio_fsroot):
    with pytest.raises(ValueError):
        fs.putfile(fileio_fsroot)


def test_uhashfs_put_fileobj_from_outside_fsroot(fs, fileio_outside_fsroot):
    address = fs.putfile(fileio_outside_fsroot)
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == fileio_outside_fsroot.read()
    assert len(list(fs.files())) == 1


def test_uhashfs_put_file_from_inside_fsroot(fs, filepath_fsroot):
    with pytest.raises(ValueError):
        fs.putfile(str(filepath_fsroot))


def test_uhashfs_put_file_from_outside_fsroot(fs, filepath_outside_fsroot):
    address = fs.putfile(str(filepath_outside_fsroot))
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes(filepath_outside_fsroot.read(), 'UTF8')
    assert len(list(fs.files())) == 1


def test_uhashfs_put_duplicate(fs, unicodestring):
    address_a = fs.putstr(unicodestring)
    address_b = fs.putstr(unicodestring)

    assert not address_a.is_duplicate
    assert address_b.is_duplicate
    assert len(list(fs.files())) == 1


def test_uhashfs_putstr(fs):
    address = fs.putstr('foo')
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes('foo', 'UTF8')
    assert len(list(fs.files())) == 1


def test_uhashfs_putstr_bytes(fs):
    address = fs.putstr(b'bar')
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes('bar', 'UTF8')

    address = fs.putstr(b'barfoo')
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes('barfoo', 'UTF8')

    assert len(list(fs.files())) == 2


def test_uhashfs_putstr_bytes_all(fs, all_bytes):
    for onebyte in all_bytes:
        address = fs.putstr(onebyte)
        assert_file_put(fs, address)
        with open(address.abspath, 'rb') as fileobj:
            assert fileobj.read() == onebyte

    assert len(list(fs.files())) == 256


def test_uhashfs_putstr_foo(fs):
    address = fs.putstr('foo')
    assert \
        address.hexdigest == \
        '76d3bc41c9f588f7fcd0d5bf4718f8f84b1c41b20882703100b9eb9413807c01' # sha3_256
    #'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae' # sha256
    assert len(list(fs.files())) == 1


def test_uhashfs_putstr_empty(fs):
    address = fs.putstr('')
    assert \
        address.hexdigest == \
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a' # sha3_256
    #'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' # sha256
    assert len(list(fs.files())) == 1


def test_uhashfs_address(fs, unicodestring):
    address = fs.putstr(unicodestring)

    assert path_is_parent(fs.root, address.abspath)
    assert address.abspath.name == address.hexdigest
    assert not address.is_duplicate
    assert len(list(fs.files())) == 1


@pytest.mark.parametrize('address_attr', [
    ('hexdigest'),
    ('hexdigest'),
    ('hexdigest'),
])
def test_uhashfs_openhexdigest(fs, unicodestring, address_attr):
    address = fs.putstr(unicodestring)

    fileobj = fs.openhexdigest(getattr(address, address_attr))

    assert isinstance(fileobj, BufferedReader)
    assert fileobj.read() == bytes(unicodestring, 'UTF8')

    fileobj.close()
    assert len(list(fs.files())) == 1


def test_uhashfs_openhexdigest_error(fs):
    with pytest.raises(ValueError):
        fs.openhexdigest('invalid')
    assert len(list(fs.files())) == 0


def test_uhashfs_existshexdigest(fs, unicodestring):
    address = fs.putstr(unicodestring)
    assert fs.existshexdigest(address.hexdigest)
    assert len(list(fs.files())) == 1


def test_uhashfs_contains(fs, unicodestring):
    address = fs.putstr(unicodestring)
    assert address.hexdigest in fs
    assert len(list(fs.files())) == 1


def test_uhashfssh1_contains(fssha1, unicodestring):
    address = fssha1.putstr(unicodestring)
    assert fssha1.algorithm == 'sha1'
    assert address.hexdigest in fssha1
    assert len(list(fssha1.files())) == 1


def test_uhashfs_relative(fs_relative):
    assert fs_relative.root.is_absolute() # it gets converted to abs
    with pytest.raises(FileNotFoundError):
        assert len(list(fs_relative.files())) == 0  # path does not exist until written to


def test_uhashfs_relative_putstr(fs_relative, unicodestring):
    fs_relative.putstr(unicodestring)
    assert fs_relative.root.is_absolute()
    assert len(list(fs_relative.files())) == 1


def test_uhashfs_gethexdigest(fs, unicodestring):
    address = fs.putstr(unicodestring)

    assert not address.is_duplicate
    assert fs.gethexdigest(address.hexdigest) == address
    with pytest.raises(ValueError):
        fs.gethexdigest('invalid')

    with pytest.raises(ValueError):
        fs.gethexdigest('0' * (fs.hexdigestlen + 1))
    with pytest.raises(ValueError):
        fs.gethexdigest('0' * (fs.hexdigestlen - 1))
    with pytest.raises(FileNotFoundError):
        fs.gethexdigest('0' * fs.hexdigestlen)
    assert len(list(fs.files())) == 1


@pytest.mark.parametrize('address_attr', [
    'hexdigest',
])
def test_uhashfs_deletehexdigest(fs, unicodestring, address_attr):
    address = fs.putstr(unicodestring)

    fs.deletehexdigest(getattr(address, address_attr))
    assert len(os.listdir(fs.root)) == 2  # _tmp and hash_folder


def test_uhashfs_deletehexdigest_error(fs):
    with pytest.raises(ValueError):
        fs.deletehexdigest('invalid')
    with pytest.raises(ValueError):
        fs.deletehexdigest('0' * (fs.hexdigestlen + 1))
    with pytest.raises(ValueError):
        fs.deletehexdigest('0' * (fs.hexdigestlen - 1))
    with pytest.raises(FileNotFoundError):
        fs.deletehexdigest('0' * fs.hexdigestlen)
    with pytest.raises(ValueError):
        fs.deletehexdigest(('0' * (fs.hexdigestlen - 1)) + 'z')
    assert len(list(fs.files())) == 0


def test_uhashfs_unshard(fs, unicodestring):
    address = fs.putstr(unicodestring)
    assert unshard(address.abspath) == address.hexdigest
    assert len(list(fs.files())) == 1


def test_uhashfs_unshard_error(fs):
    with pytest.raises(ValueError):
        unshard('invalid')
    assert len(list(fs.files())) == 0


def test_uhashfs_hexdigestpath(fs):
    assert fs.hexdigestpath('0' * fs.hexdigestlen).as_posix() == str(fs.root) + \
        os.path.sep + \
        fs.algorithm + \
        os.path.sep + \
        os.path.sep.join(list('0' * fs.depth)) + os.path.sep + \
        ('0' * fs.hexdigestlen)
    with pytest.raises(ValueError):
        fs.hexdigestpath('invalid')
    with pytest.raises(ValueError):
        fs.hexdigestpath('0' * (fs.hexdigestlen + 1))
    with pytest.raises(ValueError):
        fs.hexdigestpath('0' * (fs.hexdigestlen - 1))
    with pytest.raises(ValueError):
        fs.hexdigestpath(('0' * (fs.hexdigestlen - 1)) + 'z')
    assert len(list(fs.files())) == 0


def test_uhashfs_files(fs):
    count = 5
    addresses = putstr_range(fs, count)
    files = list(fs.files())

    assert len(files) == count

    for file in files:
        assert os.path.isfile(file)
        assert file in addresses
        assert addresses[file].abspath == file
        assert addresses[file].hexdigest == unshard(file)
    assert len(list(fs.files())) == count


def test_uhashfs_iter(fs):
    count = 5
    addresses = putstr_range(fs, count)
    test_count = 0

    for file in fs:
        test_count += 1
        assert os.path.isfile(file)
        assert file in addresses
        assert addresses[file].abspath == file
        assert addresses[file].hexdigest == unshard(file)

    assert test_count == count
    assert len(list(fs.files())) == count


def test_uhashfs_corrupted(fs, unicodestring):
    address = fs.putstr(unicodestring)
    with pytest.raises(PermissionError):
        with open(address.abspath, 'ab') as fh:
            fh.write(b'f')
    #print(address)
    os.chmod(address.abspath, 0o644)  # todo
    #import IPython
    #IPython.embed()

    assert len(list(fs.check())) == 0  # todo write file back with incorrect perms

    with open(address.abspath, 'ab') as fh:
        fh.write(b'f')
    assert len(list(fs.check())) == 1


def test_uhashfs_correct_file_count(fs):
    """len() and count() are deliberately not implemented
    because they could take "forever" to return."""
    count = 5
    putstr_range(fs, count)
    assert len(list(fs.files())) == count
