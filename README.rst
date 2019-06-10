******
uhashfs
******

uhashfs is based on HashFs: https://github.com/dgilland/hashfs

uhashfs is a content-addressable file storage and retrieval system, it manages a directory tree where files are saved based on their hash.

Typical use cases for this kind of system are ones where:

- Low memory footprint, no dameon necessary.
- Files are written once and never change (e.g. image storage).
- It's desirable to have no duplicate files (e.g. user uploads).
- File metadata is stored elsewhere (e.g. in a database or the optonal uHashFSMetadata class).


Features
========

- Files are stored once and never duplicated.
- Uses an efficient folder structure for a large number of files. File paths are based on the content hash, nested based on the first ``n`` number of characters.
- Can save files from local file paths or readable objects (open file handlers, IO buffers, etc).
- Able to index all files and find corrupted hashes.
- Supports any hashing algorithm available via ``hashlib.new``.
- Python 3.6+ compatible.
- Optional integration with https://github.com/bup/bup


Links
=====

- Project: https://github.com/jakeogh/uhashfs
- Original uHashFs Project: https://github.com/dgilland/hashfs
- PyPI: https://pypi.python.org/pypi/uhashfs (todo)


Quickstart
==========

Install using pip:

::

    pip install uhashfs (todo)


Initialization
--------------

.. code-block:: python

    from uhashfs import uHashFS


Designate a root folder for ``uHashFS``. If the folder doesn't already exist, it will be created on the first write.
A second folder (defaulting to root + '.tmp' will also be created if not specified via tmproot. It needs to reside
on the same filesystem as the root folder.

.. code-block:: python

    # Set the `depth` to the number of subfolders the file's hash should be split when saving.
    # Set the `width` to the desired width of each subfolder.
    fs = uHashFS(root='temp_hashfs', depth=4, width=1, algorithm='sha3_256')

    # With depth=4 and width=1, files will be saved in the following pattern:
    # temp_hashfs/a/b/c/d/abcdefghijklmnopqrstuvwxyz

    # With depth=3 and width=2, files will be saved in the following pattern:
    # temp_hashfs/ab/cd/ef/abcdefghijklmnopqrstuvwxyz


**NOTE:** The ``algorithm`` value should be a valid string argument to ``hashlib.new()``.


Usage
===========

``uhashfs`` supports file storage, retrieval, and removal.


Storing Content
---------------

Add content to the folder using either python3 str's or file paths (e.g. ``'a/path/to/some/file'``).


.. code-block:: python

   from uhashfs import uHashFS

   fs = uHashFS(root="/home/user/hashfs", tmpdir="/home/user/hashfs.tmp")

   address = fs.putstr('some content')

   # The id of the file (i.e. the hexdigest of its contents).
   address.id

   # The absolute path where the file was saved.
   address.abspath

   # Whether the file previously existed.
   address.is_duplicate


Retrieving File Address
-----------------------

Get a file's ``HashAddress`` by address ID. This address would be identical to the address returned by ``put()``.

.. code-block:: python

    assert fs.get(address.id) == address
    assert fs.get('invalid') is None


Retrieving Content
------------------

Get a ``BufferedReader`` handler for an existing file by address ID.

.. code-block:: python

    fileio = fs.open(address.id)


Removing Content
----------------

Delete a file by address ID or path.

.. code-block:: python

    fs.delete(address.id)


Walking Corrupted Files
-----------------------

Iterate over files that do not hash to their name.

.. code-block:: python

    for corrupted_path, expected_address in fs.corrupted():
        # do something


**WARNING:** ``uHashFS.corrupted()`` is a generator so be aware that modifying the file system while iterating could have unexpected results.


Walking All Files
-----------------

.. code-block:: python

    for file in fs.files():
        # do something

    # Or using the class' iter method...
    for file in fs:
        # do something

