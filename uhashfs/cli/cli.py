#!/usr/bin/env python3

import sys
import click
import hashlib
from uhashfs import uHashFS


@click.group()
@click.argument("root", type=click.Path(file_okay=False, resolve_path=True,
                allow_dash=True), nargs=1)
@click.option('--depth', type=int, default=3)
@click.option('--width', type=int, default=1)
@click.option('--algorithm', type=click.Choice(hashlib.algorithms_available),
              default='sha256')
@click.option('--fmode', type=int, default=0o664)
@click.option('--dmode', type=int, default=0o755)
@click.option('--verbose', is_flag=True)
@click.pass_context
def cli(ctx, root, depth, width, algorithm, fmode, dmode, verbose):
    ctx.obj = uHashFS(root, depth, width, algorithm, fmode, dmode)
    if verbose:
        print(ctx.obj, file=sys.stderr)


@cli.command()
@click.argument("infiles", type=click.File(mode='rb'), nargs=-1)
@click.pass_obj
def put(obj, infiles):
    for infile in infiles:
        item = obj.putfile(infile)
        print(item.digest, infile.name)


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
