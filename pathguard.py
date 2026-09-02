#!/usr/bin/env python3
"""Shared path-validation guard for the GeoIP toolchain (Sonar S8707).

Single source of truth — imported by extract_mmdb.py, merge_mmdb.py and
build_delta.py so every CLI-supplied path is canonicalized and confined
before any filesystem access.
"""

import os


def validated_path(path, must_exist=False):
    """Canonicalize a CLI-supplied path and confine it to the working directory.

    Guards every file access against faulty or maliciously crafted arguments:
    rejects NUL bytes, fully resolves symlinks/'..', and requires the result
    to stay inside the repository working directory.
    """
    if not path or '\x00' in path:
        raise ValueError(f'invalid path: {path!r}')
    real = os.path.realpath(path)
    root = os.path.realpath(os.getcwd())
    if real != root and not real.startswith(root + os.sep):
        raise ValueError(f'path escapes the working directory: {path!r}')
    if must_exist and not os.path.isfile(real):
        raise FileNotFoundError(path)
    return real
