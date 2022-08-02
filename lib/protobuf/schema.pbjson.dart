///
//  Generated code. Do not modify.
//  source: schema.proto
//
// @dart = 2.12
// ignore_for_file: annotate_overrides,camel_case_types,constant_identifier_names,deprecated_member_use_from_same_package,directives_ordering,library_prefixes,non_constant_identifier_names,prefer_final_fields,return_of_invalid_type,unnecessary_const,unnecessary_import,unnecessary_this,unused_import,unused_shown_name

import 'dart:core' as $core;
import 'dart:convert' as $convert;
import 'dart:typed_data' as $typed_data;
@$core.Deprecated('Use oMEMOMessageDescriptor instead')
const OMEMOMessage$json = const {
  '1': 'OMEMOMessage',
  '2': const [
    const {'1': 'n', '3': 1, '4': 2, '5': 13, '10': 'n'},
    const {'1': 'pn', '3': 2, '4': 2, '5': 13, '10': 'pn'},
    const {'1': 'dh_pub', '3': 3, '4': 2, '5': 12, '10': 'dhPub'},
    const {'1': 'ciphertext', '3': 4, '4': 1, '5': 12, '10': 'ciphertext'},
  ],
};

/// Descriptor for `OMEMOMessage`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oMEMOMessageDescriptor = $convert.base64Decode('CgxPTUVNT01lc3NhZ2USDAoBbhgBIAIoDVIBbhIOCgJwbhgCIAIoDVICcG4SFQoGZGhfcHViGAMgAigMUgVkaFB1YhIeCgpjaXBoZXJ0ZXh0GAQgASgMUgpjaXBoZXJ0ZXh0');
@$core.Deprecated('Use oMEMOAuthenticatedMessageDescriptor instead')
const OMEMOAuthenticatedMessage$json = const {
  '1': 'OMEMOAuthenticatedMessage',
  '2': const [
    const {'1': 'mac', '3': 1, '4': 2, '5': 12, '10': 'mac'},
    const {'1': 'message', '3': 2, '4': 2, '5': 12, '10': 'message'},
  ],
};

/// Descriptor for `OMEMOAuthenticatedMessage`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oMEMOAuthenticatedMessageDescriptor = $convert.base64Decode('ChlPTUVNT0F1dGhlbnRpY2F0ZWRNZXNzYWdlEhAKA21hYxgBIAIoDFIDbWFjEhgKB21lc3NhZ2UYAiACKAxSB21lc3NhZ2U=');
@$core.Deprecated('Use oMEMOKeyExchangeDescriptor instead')
const OMEMOKeyExchange$json = const {
  '1': 'OMEMOKeyExchange',
  '2': const [
    const {'1': 'pk_id', '3': 1, '4': 2, '5': 13, '10': 'pkId'},
    const {'1': 'spk_id', '3': 2, '4': 2, '5': 13, '10': 'spkId'},
    const {'1': 'ik', '3': 3, '4': 2, '5': 12, '10': 'ik'},
    const {'1': 'ek', '3': 4, '4': 2, '5': 12, '10': 'ek'},
    const {'1': 'message', '3': 5, '4': 2, '5': 11, '6': '.OMEMOAuthenticatedMessage', '10': 'message'},
  ],
};

/// Descriptor for `OMEMOKeyExchange`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oMEMOKeyExchangeDescriptor = $convert.base64Decode('ChBPTUVNT0tleUV4Y2hhbmdlEhMKBXBrX2lkGAEgAigNUgRwa0lkEhUKBnNwa19pZBgCIAIoDVIFc3BrSWQSDgoCaWsYAyACKAxSAmlrEg4KAmVrGAQgAigMUgJlaxI0CgdtZXNzYWdlGAUgAigLMhouT01FTU9BdXRoZW50aWNhdGVkTWVzc2FnZVIHbWVzc2FnZQ==');
