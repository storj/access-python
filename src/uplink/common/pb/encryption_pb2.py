# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: uplink/common/pb/encryption.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n!uplink/common/pb/encryption.proto\x12\nencryption\"Y\n\x14\x45ncryptionParameters\x12-\n\x0c\x63ipher_suite\x18\x01 \x01(\x0e\x32\x17.encryption.CipherSuite\x12\x12\n\nblock_size\x18\x02 \x01(\x03*S\n\x0b\x43ipherSuite\x12\x13\n\x0f\x45NC_UNSPECIFIED\x10\x00\x12\x0c\n\x08\x45NC_NULL\x10\x01\x12\x0e\n\nENC_AESGCM\x10\x02\x12\x11\n\rENC_SECRETBOX\x10\x03\x42\x14Z\x12storj.io/common/pbb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'uplink.common.pb.encryption_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'Z\022storj.io/common/pb'
  _globals['_CIPHERSUITE']._serialized_start=140
  _globals['_CIPHERSUITE']._serialized_end=223
  _globals['_ENCRYPTIONPARAMETERS']._serialized_start=49
  _globals['_ENCRYPTIONPARAMETERS']._serialized_end=138
# @@protoc_insertion_point(module_scope)
