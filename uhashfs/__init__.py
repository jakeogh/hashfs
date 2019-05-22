# -*- coding: utf-8 -*-
"""uhashfs is a content-addressable file management system.

It manages a directory tree where files are saved based on the file's hash.

Typical use cases for this kind of system are ones where:

- Files are written once and never change (e.g. image storage).
- It's desirable to have no duplicate files (e.g. user uploads).
- File metadata is stored elsewhere (e.g. in a database).
"""

from .__meta__ import (
    __title__,
    __summary__,
    __url__,
    __version__,
    __author__,
    __email__,
    __license__
)

from .uhashfs import uHashFS, HashAddress, unshard, path_iterator


__all__ = ('uHashFS', 'HashAddress', 'unshard', 'path_iterator')
