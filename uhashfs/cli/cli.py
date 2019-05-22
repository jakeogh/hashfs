#!/usr/bin/env python3

import os
import sys
import hashlib
from pathlib import Path
import click
from uhashfs import uHashFS
from uhashfs import path_iterator

#def all_files_iter(p):
#    if isinstance(p, str):
#        p = Path(p)
#    elif isinstance(p, bytes):
#        p = Path(os.fsdecode(p))
#        #p = p.decode()
#    assert isinstance(p, Path)
#    #print("yeilding p.absolute():", p.absolute())
#    yield p.absolute()
#    for sub in p.iterdir():
#        if sub.is_symlink():  # must be before is_dir()
#            yield sub.absolute()
#        elif sub.is_dir():
#            yield from all_files_iter(sub)
#        else:
#            yield sub.absolute()


@click.group()
@click.argument("root", type=click.Path(file_okay=False, resolve_path=True,
                                        allow_dash=True), nargs=1)
@click.option('--depth', type=int)
@click.option('--width', type=int)
@click.option('--algorithm', type=click.Choice(hashlib.algorithms_available))
@click.option('--fmode', type=int)
@click.option('--dmode', type=int)
@click.option('--redis', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.pass_context
def cli(ctx, **kwargs):
    settings = {}
    for name, value in kwargs.items():
        print(name, value)
        if value:
            settings[name] = value
    settings['root'] = Path(settings['root'])
    tmproot = settings['root'] / "tmp"
    settings['tmproot'] = tmproot
    if 'verbose' not in settings.keys():
        settings['verbose'] = False
    ctx.obj = uHashFS(**settings)
    if settings['verbose']:
        print(ctx.obj, file=sys.stderr)


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


@cli.command()
@click.argument("infiles", type=click.Path(exists=True), nargs=-1)
@click.option('--recursive', is_flag=True)
@click.pass_obj
def put(obj, infiles, recursive):
    path_iter = path_iterator(infile).go()
    for infile in infiles:
        print("infile:", infile)
        if recursive:
            for item in path_iter(infile):
                print(item.absolute)  # yep. that's ugly. you cant just print Path objects
                if really_is_file(item):
                    newitem = obj.putfile(item)
                else:
                    print("notafile item:", bytes(item))
                    print("notafile item:", item.absolute)  # deliberate, dont "fix"
                    try:
                        assert really_is_dir(item)
                    except AssertionError:
                        try:
                            item.is_symlink()
                        except OSError as e:
                            assert '[Errno 40] Too many levels of symbolic links:' in e.strerror
        else:
            print("else:", infile)
            newitem = obj.putfile(infile)

        print(newitem.hexdigest, infile)


@cli.command()
@click.argument("digests", type=str, nargs=-1)
@click.pass_obj
def get(obj, digests):
    for digest in digests:
        item = obj.get(digest)
        print(item.abspath)


@cli.command()
@click.argument("digests", type=str, nargs=-1)
@click.pass_obj
def delete(obj, digests):
    for digest in digests:
        try:
            ans = obj.delete(digest)
        except FileNotFoundError:
            ans = False
        print("delete:", digest + ':', ans)


@cli.command()
@click.pass_obj
def iterate(obj):
    for hashfile in obj.files():
        print("file:", hashfile)


@cli.command()
@click.pass_obj
def checkcorrupt(obj):
    for hashfile in obj.corrupted():
        print("corrupt:", hashfile)


if __name__ == '__main__':
    cli()
