#!/usr/bin/env python3

import os
import sys
import hashlib
import humanize
from pathlib import Path
import click
from uhashfs import uHashFS
from uhashfs import uHashFSMetadata
from uhashfs import Path_Iterator
from uhashfs import really_is_file
from uhashfs import really_is_dir

ALGS = list(hashlib.algorithms_available)
ALGS.sort()


@click.group()
@click.argument("root", type=click.Path(file_okay=False, resolve_path=True,
                                        allow_dash=True), nargs=1)
@click.option("--metaroot", type=click.Path(file_okay=False, resolve_path=True,
                                            allow_dash=True))
@click.option('--width', type=click.IntRange(1, 3))
@click.option('--depth', type=click.IntRange(1, 6))
@click.option('--algorithm', type=click.Choice(ALGS))
@click.option('--fmode', type=int)
@click.option('--dmode', type=int)
@click.option('--disable-redis', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.option('--legacy', is_flag=True)
@click.pass_context
def cli(ctx, **kwargs):
    settings = {}
    meta_settings = {}
    for name, value in kwargs.items():
        #print(name, value)
        if name == 'disable_redis':
            if not value:  # enable it
                settings['redis'] = True
            else:  # disable it
                settings['redis'] = False
        elif value:
            if name == "metaroot":
                meta_settings[name] = value
            else:
                settings[name] = value
    settings['root'] = Path(settings['root'])
    #tmproot = settings['root'] / "tmp"
    #settings['tmproot'] = tmproot
    if 'verbose' not in settings.keys():
        settings['verbose'] = False
    data_fs = uHashFS(**settings)
    if 'metaroot' in meta_settings.keys():
        settings['uhashfs'] = data_fs
        settings['root'] = Path(meta_settings['metaroot'])
        #meta_fs = uHashFSMetadata(root=meta_settings['metaroot'], uhashfs=data_fs, verbose=settings['verbose'])
        meta_fs = uHashFSMetadata(**settings)
        ctx.obj = meta_fs
    else:
        ctx.obj = data_fs
    if settings['verbose']:
        print(ctx.obj, file=sys.stderr)


@cli.command()
@click.argument("infiles", type=click.Path(exists=True), nargs=-1)
@click.option('--recursive', is_flag=True)
@click.pass_obj
def put(obj, infiles, recursive):
    for infile in infiles:
        path_iter = Path_Iterator(infile).go()
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
        item = obj.gethexdigest(digest)
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
        print(hashfile)


@cli.command()
@click.option("--variance", type=click.FloatRange(0, 100), default=0.001)  # 100 is arb
@click.option('--verbose', is_flag=True)
@click.pass_obj
def estimate_edge_properites(obj, variance, verbose):
    if verbose:
        obj.verbose = True
    objects, size = obj.estimate_edge_properites(variance)
    print(humanize.intcomma(objects), humanize.naturalsize(size))


@cli.command()
@click.option("--variance", type=click.FloatRange(0, 100), default=0.001)  # 100 is arb
@click.option('--verbose', is_flag=True)
@click.pass_obj
def estimate_tree_properites(obj, variance, verbose):
    if verbose:
        obj.verbose = True
    objects, size = obj.estimate_tree_properites(variance)
    print(humanize.intcomma(objects), humanize.naturalsize(size))


@cli.command()
@click.pass_obj
def ipython(obj):
    import IPython
    IPython.embed()


@cli.command()
@click.option('--delete-empty', is_flag=True)
@click.option('--dont-skip-cached', is_flag=True)
@click.option('--quiet', is_flag=True)
@click.option('--verbose', is_flag=True)
@click.pass_obj
def check(obj, delete_empty, dont_skip_cached, quiet):
    if verbose:
        obj.verbose = True
    skip_cached = not dont_skip_cached
    if not skip_cached:
        print("Warning: not skipping hashes already cached in redis.", file=sys.stderr)
    for path, expected_hash in obj.check(skip_cached=skip_cached, quiet=quiet):
        print(path)
        if expected_hash.fs.emptyhexdigest:
            print("path:", path, "matches the emptydigest for", expected_hash.fs.algorithm, file=sys.stderr)
            if delete_empty:
                os.unlink(path)
                print("deleted:", path, file=sys.stderr)


if __name__ == '__main__':
    cli()
