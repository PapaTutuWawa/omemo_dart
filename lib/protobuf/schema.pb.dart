///
//  Generated code. Do not modify.
//  source: schema.proto
//
// @dart = 2.12
// ignore_for_file: annotate_overrides,camel_case_types,constant_identifier_names,directives_ordering,library_prefixes,non_constant_identifier_names,prefer_final_fields,return_of_invalid_type,unnecessary_const,unnecessary_import,unnecessary_this,unused_import,unused_shown_name

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

class OMEMOMessage extends $pb.GeneratedMessage {
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(const $core.bool.fromEnvironment('protobuf.omit_message_names') ? '' : 'OMEMOMessage', createEmptyInstance: create)
    ..a<$core.int>(1, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'n', $pb.PbFieldType.QU3)
    ..a<$core.int>(2, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'pn', $pb.PbFieldType.QU3)
    ..a<$core.List<$core.int>>(3, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'dhPub', $pb.PbFieldType.QY)
    ..a<$core.List<$core.int>>(4, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'ciphertext', $pb.PbFieldType.OY)
  ;

  OMEMOMessage._() : super();
  factory OMEMOMessage({
    $core.int? n,
    $core.int? pn,
    $core.List<$core.int>? dhPub,
    $core.List<$core.int>? ciphertext,
  }) {
    final _result = create();
    if (n != null) {
      _result.n = n;
    }
    if (pn != null) {
      _result.pn = pn;
    }
    if (dhPub != null) {
      _result.dhPub = dhPub;
    }
    if (ciphertext != null) {
      _result.ciphertext = ciphertext;
    }
    return _result;
  }
  factory OMEMOMessage.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory OMEMOMessage.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  OMEMOMessage clone() => OMEMOMessage()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  OMEMOMessage copyWith(void Function(OMEMOMessage) updates) => super.copyWith((message) => updates(message as OMEMOMessage)) as OMEMOMessage; // ignore: deprecated_member_use
  $pb.BuilderInfo get info_ => _i;
  @$core.pragma('dart2js:noInline')
  static OMEMOMessage create() => OMEMOMessage._();
  OMEMOMessage createEmptyInstance() => create();
  static $pb.PbList<OMEMOMessage> createRepeated() => $pb.PbList<OMEMOMessage>();
  @$core.pragma('dart2js:noInline')
  static OMEMOMessage getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<OMEMOMessage>(create);
  static OMEMOMessage? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get n => $_getIZ(0);
  @$pb.TagNumber(1)
  set n($core.int v) { $_setUnsignedInt32(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasN() => $_has(0);
  @$pb.TagNumber(1)
  void clearN() => clearField(1);

  @$pb.TagNumber(2)
  $core.int get pn => $_getIZ(1);
  @$pb.TagNumber(2)
  set pn($core.int v) { $_setUnsignedInt32(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasPn() => $_has(1);
  @$pb.TagNumber(2)
  void clearPn() => clearField(2);

  @$pb.TagNumber(3)
  $core.List<$core.int> get dhPub => $_getN(2);
  @$pb.TagNumber(3)
  set dhPub($core.List<$core.int> v) { $_setBytes(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasDhPub() => $_has(2);
  @$pb.TagNumber(3)
  void clearDhPub() => clearField(3);

  @$pb.TagNumber(4)
  $core.List<$core.int> get ciphertext => $_getN(3);
  @$pb.TagNumber(4)
  set ciphertext($core.List<$core.int> v) { $_setBytes(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasCiphertext() => $_has(3);
  @$pb.TagNumber(4)
  void clearCiphertext() => clearField(4);
}

class OMEMOAuthenticatedMessage extends $pb.GeneratedMessage {
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(const $core.bool.fromEnvironment('protobuf.omit_message_names') ? '' : 'OMEMOAuthenticatedMessage', createEmptyInstance: create)
    ..a<$core.List<$core.int>>(1, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'mac', $pb.PbFieldType.QY)
    ..a<$core.List<$core.int>>(2, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'message', $pb.PbFieldType.QY)
  ;

  OMEMOAuthenticatedMessage._() : super();
  factory OMEMOAuthenticatedMessage({
    $core.List<$core.int>? mac,
    $core.List<$core.int>? message,
  }) {
    final _result = create();
    if (mac != null) {
      _result.mac = mac;
    }
    if (message != null) {
      _result.message = message;
    }
    return _result;
  }
  factory OMEMOAuthenticatedMessage.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory OMEMOAuthenticatedMessage.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  OMEMOAuthenticatedMessage clone() => OMEMOAuthenticatedMessage()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  OMEMOAuthenticatedMessage copyWith(void Function(OMEMOAuthenticatedMessage) updates) => super.copyWith((message) => updates(message as OMEMOAuthenticatedMessage)) as OMEMOAuthenticatedMessage; // ignore: deprecated_member_use
  $pb.BuilderInfo get info_ => _i;
  @$core.pragma('dart2js:noInline')
  static OMEMOAuthenticatedMessage create() => OMEMOAuthenticatedMessage._();
  OMEMOAuthenticatedMessage createEmptyInstance() => create();
  static $pb.PbList<OMEMOAuthenticatedMessage> createRepeated() => $pb.PbList<OMEMOAuthenticatedMessage>();
  @$core.pragma('dart2js:noInline')
  static OMEMOAuthenticatedMessage getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<OMEMOAuthenticatedMessage>(create);
  static OMEMOAuthenticatedMessage? _defaultInstance;

  @$pb.TagNumber(1)
  $core.List<$core.int> get mac => $_getN(0);
  @$pb.TagNumber(1)
  set mac($core.List<$core.int> v) { $_setBytes(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasMac() => $_has(0);
  @$pb.TagNumber(1)
  void clearMac() => clearField(1);

  @$pb.TagNumber(2)
  $core.List<$core.int> get message => $_getN(1);
  @$pb.TagNumber(2)
  set message($core.List<$core.int> v) { $_setBytes(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasMessage() => $_has(1);
  @$pb.TagNumber(2)
  void clearMessage() => clearField(2);
}

class OMEMOKeyExchange extends $pb.GeneratedMessage {
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(const $core.bool.fromEnvironment('protobuf.omit_message_names') ? '' : 'OMEMOKeyExchange', createEmptyInstance: create)
    ..a<$core.int>(1, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'pkId', $pb.PbFieldType.QU3)
    ..a<$core.int>(2, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'spkId', $pb.PbFieldType.QU3)
    ..a<$core.List<$core.int>>(3, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'ik', $pb.PbFieldType.QY)
    ..a<$core.List<$core.int>>(4, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'ek', $pb.PbFieldType.QY)
    ..aQM<OMEMOAuthenticatedMessage>(5, const $core.bool.fromEnvironment('protobuf.omit_field_names') ? '' : 'message', subBuilder: OMEMOAuthenticatedMessage.create)
  ;

  OMEMOKeyExchange._() : super();
  factory OMEMOKeyExchange({
    $core.int? pkId,
    $core.int? spkId,
    $core.List<$core.int>? ik,
    $core.List<$core.int>? ek,
    OMEMOAuthenticatedMessage? message,
  }) {
    final _result = create();
    if (pkId != null) {
      _result.pkId = pkId;
    }
    if (spkId != null) {
      _result.spkId = spkId;
    }
    if (ik != null) {
      _result.ik = ik;
    }
    if (ek != null) {
      _result.ek = ek;
    }
    if (message != null) {
      _result.message = message;
    }
    return _result;
  }
  factory OMEMOKeyExchange.fromBuffer($core.List<$core.int> i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromBuffer(i, r);
  factory OMEMOKeyExchange.fromJson($core.String i, [$pb.ExtensionRegistry r = $pb.ExtensionRegistry.EMPTY]) => create()..mergeFromJson(i, r);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.deepCopy] instead. '
  'Will be removed in next major version')
  OMEMOKeyExchange clone() => OMEMOKeyExchange()..mergeFromMessage(this);
  @$core.Deprecated(
  'Using this can add significant overhead to your binary. '
  'Use [GeneratedMessageGenericExtensions.rebuild] instead. '
  'Will be removed in next major version')
  OMEMOKeyExchange copyWith(void Function(OMEMOKeyExchange) updates) => super.copyWith((message) => updates(message as OMEMOKeyExchange)) as OMEMOKeyExchange; // ignore: deprecated_member_use
  $pb.BuilderInfo get info_ => _i;
  @$core.pragma('dart2js:noInline')
  static OMEMOKeyExchange create() => OMEMOKeyExchange._();
  OMEMOKeyExchange createEmptyInstance() => create();
  static $pb.PbList<OMEMOKeyExchange> createRepeated() => $pb.PbList<OMEMOKeyExchange>();
  @$core.pragma('dart2js:noInline')
  static OMEMOKeyExchange getDefault() => _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<OMEMOKeyExchange>(create);
  static OMEMOKeyExchange? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get pkId => $_getIZ(0);
  @$pb.TagNumber(1)
  set pkId($core.int v) { $_setUnsignedInt32(0, v); }
  @$pb.TagNumber(1)
  $core.bool hasPkId() => $_has(0);
  @$pb.TagNumber(1)
  void clearPkId() => clearField(1);

  @$pb.TagNumber(2)
  $core.int get spkId => $_getIZ(1);
  @$pb.TagNumber(2)
  set spkId($core.int v) { $_setUnsignedInt32(1, v); }
  @$pb.TagNumber(2)
  $core.bool hasSpkId() => $_has(1);
  @$pb.TagNumber(2)
  void clearSpkId() => clearField(2);

  @$pb.TagNumber(3)
  $core.List<$core.int> get ik => $_getN(2);
  @$pb.TagNumber(3)
  set ik($core.List<$core.int> v) { $_setBytes(2, v); }
  @$pb.TagNumber(3)
  $core.bool hasIk() => $_has(2);
  @$pb.TagNumber(3)
  void clearIk() => clearField(3);

  @$pb.TagNumber(4)
  $core.List<$core.int> get ek => $_getN(3);
  @$pb.TagNumber(4)
  set ek($core.List<$core.int> v) { $_setBytes(3, v); }
  @$pb.TagNumber(4)
  $core.bool hasEk() => $_has(3);
  @$pb.TagNumber(4)
  void clearEk() => clearField(4);

  @$pb.TagNumber(5)
  OMEMOAuthenticatedMessage get message => $_getN(4);
  @$pb.TagNumber(5)
  set message(OMEMOAuthenticatedMessage v) { setField(5, v); }
  @$pb.TagNumber(5)
  $core.bool hasMessage() => $_has(4);
  @$pb.TagNumber(5)
  void clearMessage() => clearField(5);
  @$pb.TagNumber(5)
  OMEMOAuthenticatedMessage ensureMessage() => $_ensure(4);
}

