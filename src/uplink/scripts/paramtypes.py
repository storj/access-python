# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

import datetime

import click

from uplink.common import grant
from .location import Location


class SharePrefix(click.ParamType):
    name = "prefix"

    def convert(self, value, param, ctx):
        if isinstance(value, grant.SharePrefix):
            return value
        loc = Location.parse(value)
        bucket, key, ok = loc.remote_parts()
        if not ok:
            raise ValueError(f"invalid prefix: must be remote: {loc}")
        return grant.SharePrefix(bucket.encode(), key.encode())


class HumanDateNotBefore(click.ParamType):
    name = "not_before"

    def convert(self, value, param, ctx):
        return _convert_human_date(value, False)


class HumanDateNotAfter(click.ParamType):
    name = "not_after"

    def convert(self, value, param, ctx):
        return _convert_human_date(value, True)


class Duration(click.ParamType):
    name = "duration"

    def convert(self, value, param, ctx):
        if isinstance(value, datetime.timedelta):
            return value
        raise Exception("not implemented yet")


def _convert_human_date(value: str, ceil: bool):
    if isinstance(value, datetime.datetime):
        return value
    raise Exception("not implemented yet")
