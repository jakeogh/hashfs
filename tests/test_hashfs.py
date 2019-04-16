# -*- coding: utf-8 -*-

from io import BufferedReader
import os
import string
import py
import pytest
import time
from hashfs import HashFS, unshard

TIMESTAMP = str(time.time())


@pytest.fixture
def testpath_outside_fsroot(tmpdir):
    return tmpdir.mkdir('hashfs_input_files_' + TIMESTAMP)


@pytest.fixture
def testpath_fsroot(tmpdir):
    return tmpdir.mkdir('hashfs_root' + TIMESTAMP)


@pytest.fixture
def fs_relative():
    return HashFS('relative_path' + TIMESTAMP)


@pytest.fixture
def testfile_outside_fsroot(testpath_outside_fsroot):
    return testpath_outside_fsroot.join('hashfs.txt')


@pytest.fixture
def testfile_fsroot(testpath_fsroot):
    return testpath_fsroot.join('hashfs.txt')


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
    return HashFS(str(testpath_fsroot))


@pytest.fixture
def fssha1(testpath_fsroot):
    return HashFS(str(testpath_fsroot), algorithm='sha1')


def putstr_range(fs, count):
    return dict((address.abspath, address)
                for address in (fs.putstr(u'{0}'.format(i))
                                for i in range(count)))


def assert_file_put(fs, address):
    directory = os.path.dirname(address.abspath)
    reldirectory = str(directory).split(str(fs.root))[-1]
    dir_parts = [part for part in reldirectory.split(os.path.sep) if part]

    assert address.abspath in tuple(py.path.local(fs.root).visit())
    assert fs.exists(address.digest)

    digest = str(address.abspath).split(os.path.sep)[-1]
    assert digest == address.digest

    assert len(dir_parts) == fs.depth
    assert all(len(part) == fs.width for part in dir_parts)
    # assert len(list(fs.files())) == 1


def test_hashfs_put_fileobj_from_inside_root(fs, fileio_fsroot):
    with pytest.raises(ValueError):
        fs.putfile(fileio_fsroot)


def test_hashfs_put_fileobj_from_outside_fsroot(fs, fileio_outside_fsroot):
    address = fs.putfile(fileio_outside_fsroot)
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == fileio_outside_fsroot.read()
    assert len(list(fs.files())) == 1


def test_hashfs_put_file_from_inside_fsroot(fs, filepath_fsroot):
    with pytest.raises(ValueError):
        fs.putfile(str(filepath_fsroot))


def test_hashfs_put_file_from_outside_fsroot(fs, filepath_outside_fsroot):
    address = fs.putfile(str(filepath_outside_fsroot))
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes(filepath_outside_fsroot.read(), 'UTF8')
    assert len(list(fs.files())) == 1


def test_hashfs_put_duplicate(fs, unicodestring):
    address_a = fs.putstr(unicodestring)
    address_b = fs.putstr(unicodestring)

    assert not address_a.is_duplicate
    assert address_b.is_duplicate
    assert len(list(fs.files())) == 1


def test_hashfs_putstr(fs):
    address = fs.putstr('foo')
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes('foo', 'UTF8')
    assert len(list(fs.files())) == 1


def test_hashfs_putstr_bytes(fs):
    address = fs.putstr(b'bar')
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes('bar', 'UTF8')

    address = fs.putstr(b'barfoo')
    assert_file_put(fs, address)
    with open(address.abspath, 'rb') as fileobj:
        assert fileobj.read() == bytes('barfoo', 'UTF8')

    assert len(list(fs.files())) == 2


def test_hashfs_putstr_bytes_all(fs, all_bytes):
    for onebyte in all_bytes:
        address = fs.putstr(onebyte)
        assert_file_put(fs, address)
        with open(address.abspath, 'rb') as fileobj:
            assert fileobj.read() == onebyte

    assert len(list(fs.files())) == 256


def test_hashfs_putstr_foo(fs):
    address = fs.putstr('foo')
    assert \
        address.digest == \
        '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
    assert len(list(fs.files())) == 1


def test_hashfs_putstr_empty(fs):
    address = fs.putstr('')
    assert \
        address.digest == \
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    assert len(list(fs.files())) == 1


def test_hashfs_address(fs, unicodestring):
    address = fs.putstr(unicodestring)

    assert str(fs.root) in address.abspath
    assert address.abspath.split(os.path.sep)[-1] == address.digest
    assert not address.is_duplicate
    assert len(list(fs.files())) == 1


@pytest.mark.parametrize('address_attr', [
    ('digest'),
    ('digest'),
    ('digest'),
])
def test_hashfs_open(fs, unicodestring, address_attr):
    address = fs.putstr(unicodestring)

    fileobj = fs.open(getattr(address, address_attr))

    assert isinstance(fileobj, BufferedReader)
    assert fileobj.read() == bytes(unicodestring, 'UTF8')

    fileobj.close()
    assert len(list(fs.files())) == 1


def test_hashfs_open_error(fs):
    with pytest.raises(ValueError):
        fs.open('invalid')
    assert len(list(fs.files())) == 0


def test_hashfs_exists(fs, unicodestring):
    address = fs.putstr(unicodestring)
    assert fs.exists(address.digest)
    assert len(list(fs.files())) == 1


def test_hashfs_contains(fs, unicodestring):
    address = fs.putstr(unicodestring)
    assert address.digest in fs
    assert len(list(fs.files())) == 1


def test_hashfssh1_contains(fssha1, unicodestring):
    address = fssha1.putstr(unicodestring)
    assert fssha1.algorithm == 'sha1'
    assert address.digest in fssha1
    assert len(list(fssha1.files())) == 1


def test_hashfs_relative(fs_relative):
    assert os.path.sep in str(fs_relative.root)
    assert str(fs_relative.root).startswith(os.path.sep)
    assert len(list(fs_relative.files())) == 0


def test_hashfs_relative_putstr(fs_relative, unicodestring):
    fs_relative.putstr(unicodestring)
    assert os.path.sep in str(fs_relative.root)
    assert str(fs_relative.root).startswith(os.path.sep)
    assert len(list(fs_relative.files())) == 1


def test_hashfs_get(fs, unicodestring):
    address = fs.putstr(unicodestring)

    assert not address.is_duplicate
    assert fs.get(address.digest) == address
    with pytest.raises(ValueError):
        fs.get('invalid')

    with pytest.raises(ValueError):
        fs.get('0' * (fs.digestlen + 1))
    with pytest.raises(ValueError):
        fs.get('0' * (fs.digestlen - 1))
    with pytest.raises(FileNotFoundError):
        fs.get('0' * fs.digestlen)
    assert len(list(fs.files())) == 1


@pytest.mark.parametrize('address_attr', [
    'digest',
])
def test_hashfs_delete(fs, unicodestring, address_attr):
    address = fs.putstr(unicodestring)

    fs.delete(getattr(address, address_attr))
    assert len(os.listdir(fs.root)) == 1


def test_hashfs_delete_error(fs):
    with pytest.raises(ValueError):
        fs.delete('invalid')
    with pytest.raises(ValueError):
        fs.delete('0' * (fs.digestlen + 1))
    with pytest.raises(ValueError):
        fs.delete('0' * (fs.digestlen - 1))
    with pytest.raises(FileNotFoundError):
        fs.delete('0' * fs.digestlen)
    with pytest.raises(ValueError):
        fs.delete(('0' * (fs.digestlen - 1)) + 'z')
    assert len(list(fs.files())) == 0


def test_hashfs_unshard(fs, unicodestring):
    address = fs.putstr(unicodestring)
    assert unshard(address.abspath) == address.digest
    assert len(list(fs.files())) == 1


def test_hashfs_unshard_error(fs):
    with pytest.raises(ValueError):
        unshard('invalid')
    assert len(list(fs.files())) == 0


def test_hashfs_digestpath(fs):
    assert fs.digestpath('0' * fs.digestlen) == str(fs.root) + os.path.sep + \
        os.path.sep.join(list('0' * fs.depth)) + os.path.sep + \
        ('0' * fs.digestlen)
    with pytest.raises(ValueError):
        fs.digestpath('invalid')
    with pytest.raises(ValueError):
        fs.digestpath('0' * (fs.digestlen + 1))
    with pytest.raises(ValueError):
        fs.digestpath('0' * (fs.digestlen - 1))
    with pytest.raises(ValueError):
        fs.digestpath(('0' * (fs.digestlen - 1)) + 'z')
    assert len(list(fs.files())) == 0


def test_hashfs_files(fs):
    count = 5
    addresses = putstr_range(fs, count)
    files = list(fs.files())

    assert len(files) == count

    for file in files:
        assert os.path.isfile(file)
        assert file in addresses
        assert addresses[file].abspath == file
        assert addresses[file].digest == unshard(file)
    assert len(list(fs.files())) == count


def test_hashfs_iter(fs):
    count = 5
    addresses = putstr_range(fs, count)
    test_count = 0

    for file in fs:
        test_count += 1
        assert os.path.isfile(file)
        assert file in addresses
        assert addresses[file].abspath == file
        assert addresses[file].digest == unshard(file)

    assert test_count == count
    assert len(list(fs.files())) == count


def test_hashfs_corrupted(fs, unicodestring):
    address = fs.putstr(unicodestring)
    with open(address.abspath, 'ab') as fh:
        fh.write(b'f')
    assert len(list(fs.corrupted())) == 1


def test_hashfs_correct_file_count(fs):
    """len() and count() are deliberately not implemented
    because they could take "forever" to return."""
    count = 5
    putstr_range(fs, count)
    assert len(list(fs.files())) == count
