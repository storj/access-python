# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from os.path import normpath
from typing import Optional


class Location:
    __slots__ = ["_std", "_bucket", "_loc"]

    def __init__(self):
        self._std = False
        self._bucket = ""
        self._loc = ""

    @staticmethod
    def parse(location):
        if location == "-":
            return Location.newstd()
        if location.startswith("sj://") or location.startswith("s3://"):
            trimmed = location[5:]
            idx = trimmed.find("/")
            if len(trimmed) == 0 or idx == 0:
                raise Exception(f"invalid path: empty bucket in path '{location}'")
            if idx == -1:
                bucket, key = trimmed, ""
            else:
                bucket, key = trimmed[:idx], trimmed[idx + 1 :]
            return Location.newremote(bucket, key)
        return Location.newlocal(location)

    @staticmethod
    def newlocal(loc):
        location = Location()
        location._loc = clean_path(loc)
        return location

    @staticmethod
    def newremote(bucket, key):
        location = Location()
        location._bucket = bucket
        location._loc = key
        return location

    @staticmethod
    def newstd():
        location = Location()
        location._std = True
        return location

    def __str__(self):
        if self.std:
            return "-"
        elif self.remote:
            return f"sj://{self._bucket}/{self._loc}"
        return self.loc

    @property
    def parent(self):
        if self.std:
            return ""
        idx = self._loc.rfind("/")
        return "" if idx == -1 else self._loc[: idx + 1]

    def base(self):
        if self.std:
            return "", False
        idx = self._loc.rfind("/")
        base = self._loc if idx == -1 else self._loc[idx + 1 :]
        return base, len(base) > 0

    def relative_to(self, target):
        if self.std or target.std:
            raise ValueError("cannot create relative location for stdin/stdout")
        if target.remote != self.remote:
            raise ValueError("cannot create remote and local relative location")
        if target.bucket != self._bucket:
            raise ValueError("cannot change buckets in relative remote location")
        if not target.loc.startswith(self.loc):
            raise ValueError(
                "cannot make relative location because keys are not prefixes"
            )
        idx = self.loc.rfind("/") + 1
        return target.loc[idx:]

    def remote_parts(self):
        return self._bucket, self._loc, self.remote

    @property
    def loc(self):
        return self._loc

    @property
    def std(self):
        return self._std

    @property
    def remote(self):
        return not self.std and bool(self._bucket)

    @property
    def local(self):
        return not self.std and not bool(self._bucket)


def clean_path(path):
    cleaned = normpath(path)

    if cleaned != "" and path.endswith("/"):
        return cleaned + "/"

    return cleaned
