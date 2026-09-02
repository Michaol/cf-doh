#!/usr/bin/env python3
"""Shared SQL batch emission for the GeoIP toolchain.

Single source of truth for statement batching and literal quoting — used by
build_delta.py (convergence deltas) and build_chunks.py (bootstrap trickle).
"""

MAX_STMT_BYTES = 80_000  # D1 hard limit is 100KB per statement; keep margin


def sql_str(s):
    """Quote a SQL text literal (single-quote escaping)."""
    return "'" + s.replace("'", "''") + "'"


def iter_batches(head, tail, pieces, max_bytes=MAX_STMT_BYTES):
    """Yield multi-row statements: head + comma-joined pieces + tail.

    Splits whenever the accumulated statement would exceed the byte budget.
    """
    batch, size = [], len(head) + len(tail)
    for piece in pieces:
        if batch and size + len(piece) + 1 > max_bytes:
            yield head + ",".join(batch) + tail
            batch, size = [], len(head) + len(tail)
        batch.append(piece)
        size += len(piece) + 1
    if batch:
        yield head + ",".join(batch) + tail
