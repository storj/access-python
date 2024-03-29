"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
Copyright (C) 2019 Storj Labs, Inc.
See LICENSE for copying information.
"""
import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.duration_pb2
import google.protobuf.internal.containers
import google.protobuf.message
import google.protobuf.timestamp_pb2
import sys

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing_extensions.final
class Caveat(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    @typing_extensions.final
    class Path(google.protobuf.message.Message):
        """If any entries exist, require all access to happen in at least
        one of them.
        """

        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        BUCKET_FIELD_NUMBER: builtins.int
        ENCRYPTED_PATH_PREFIX_FIELD_NUMBER: builtins.int
        bucket: builtins.bytes
        encrypted_path_prefix: builtins.bytes
        def __init__(
            self,
            *,
            bucket: builtins.bytes = ...,
            encrypted_path_prefix: builtins.bytes = ...,
        ) -> None: ...
        def ClearField(self, field_name: typing_extensions.Literal["bucket", b"bucket", "encrypted_path_prefix", b"encrypted_path_prefix"]) -> None: ...

    DISALLOW_READS_FIELD_NUMBER: builtins.int
    DISALLOW_WRITES_FIELD_NUMBER: builtins.int
    DISALLOW_LISTS_FIELD_NUMBER: builtins.int
    DISALLOW_DELETES_FIELD_NUMBER: builtins.int
    ALLOWED_PATHS_FIELD_NUMBER: builtins.int
    NOT_AFTER_FIELD_NUMBER: builtins.int
    NOT_BEFORE_FIELD_NUMBER: builtins.int
    MAX_OBJECT_TTL_FIELD_NUMBER: builtins.int
    NONCE_FIELD_NUMBER: builtins.int
    disallow_reads: builtins.bool
    """if any of these three are set, disallow that type of access"""
    disallow_writes: builtins.bool
    disallow_lists: builtins.bool
    disallow_deletes: builtins.bool
    @property
    def allowed_paths(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___Caveat.Path]: ...
    @property
    def not_after(self) -> google.protobuf.timestamp_pb2.Timestamp:
        """if set, the validity time window"""
    @property
    def not_before(self) -> google.protobuf.timestamp_pb2.Timestamp: ...
    @property
    def max_object_ttl(self) -> google.protobuf.duration_pb2.Duration:
        """if set, sets expiration time for new objects"""
    nonce: builtins.bytes
    """nonce is set to some random bytes so that you can make arbitrarily
    many restricted macaroons with the same (or no) restrictions.
    """
    def __init__(
        self,
        *,
        disallow_reads: builtins.bool = ...,
        disallow_writes: builtins.bool = ...,
        disallow_lists: builtins.bool = ...,
        disallow_deletes: builtins.bool = ...,
        allowed_paths: collections.abc.Iterable[global___Caveat.Path] | None = ...,
        not_after: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        not_before: google.protobuf.timestamp_pb2.Timestamp | None = ...,
        max_object_ttl: google.protobuf.duration_pb2.Duration | None = ...,
        nonce: builtins.bytes = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["max_object_ttl", b"max_object_ttl", "not_after", b"not_after", "not_before", b"not_before"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["allowed_paths", b"allowed_paths", "disallow_deletes", b"disallow_deletes", "disallow_lists", b"disallow_lists", "disallow_reads", b"disallow_reads", "disallow_writes", b"disallow_writes", "max_object_ttl", b"max_object_ttl", "nonce", b"nonce", "not_after", b"not_after", "not_before", b"not_before"]) -> None: ...

global___Caveat = Caveat
