//
//  NearbyConnection.swift
//  NearDrop
//
//  Created by Grishka on 09.04.2023.
//

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crossdrop/nearby_share/protobuf/offline_wire_formats.pb.dart'
    as LocationNearbyConnections;
import 'package:crossdrop/nearby_share/protobuf/wire_format.pb.dart'
    as SharingNearby;
import 'package:cryptography/cryptography.dart';
import 'package:fixnum/fixnum.dart';
import 'package:pointycastle/export.dart';
import 'package:crossdrop/nearby_share/protobuf/pb.dart';

class NearbyConnection {
  final Socket connection;
  RemoteDeviceInfo? remoteDeviceInfo;
  final Map<int, Uint8List> payloadBuffers = {};
  bool encryptionDone = false;
  final Map<int, InternalFileInfo> transferredFiles = {};
  final String id;
  Error? lastError;
  bool connectionClosed = false;

  static const SANE_FRAME_LENGTH = 5 * 1024 * 1024;

  // UKEY2-related state
  ECPublicKey? publicKey;
  ECPrivateKey? privateKey;
  Uint8List? ukeyClientInitMsgData;
  Uint8List? ukeyServerInitMsgData;

  // SecureMessage encryption keys
  List<int>? decryptKey;
  List<int>? encryptKey;
  SecretKey? recvHmacKey;
  SecretKey? sendHmacKey;

  // SecureMessage sequence numbers
  int serverSeq = 0;
  int clientSeq = 0;

  String? pinCode;

  NearbyConnection({required this.connection, required this.id});

  void start() {
    connection.listen(
      (data) {
        receiveFrameAsync();
      },
      onError: (err) {
        lastError = err as Error;
        print('Error opening socket: $err');
        handleConnectionClosure();
      },
      onDone: () {
        handleConnectionClosure();
      },
    );
  }

  void handleConnectionClosure() {
    print('Connection closed');
  }

  void protocolError() {
    disconnect();
  }

  void processReceivedFrame(Uint8List frameData) {
    throw UnimplementedError();
  }

  Future<void> processTransferSetupFrame(SharingNearby.Frame frame) {
    throw UnimplementedError();
  }

  bool isServer() {
    throw UnimplementedError();
  }

  Future<void> processFileChunk(
      {required LocationNearbyConnections.PayloadTransferFrame frame}) {
    protocolError();
    return Future(() => null);
  }

  void receiveFrameAsync() {
    connection.listen(
      (data) {
        if (connectionClosed) {
          return;
        }
        if (data.length < 4) {
          handleConnectionClosure();
          return;
        }
        int frameLength =
            data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
        if (frameLength > NearbyConnection.SANE_FRAME_LENGTH) {
          throw NearbyError.protocolError('Unexpected packet length');
        }
        receiveFrameAsyncLength(length: frameLength);
      },
      onError: (err) {
        lastError = err as Error;
        protocolError();
      },
      onDone: () {
        handleConnectionClosure();
      },
    );
  }

  void receiveFrameAsyncLength({required int length}) {
    connection.listen(
      (data) {
        if (connectionClosed) {
          return;
        }
        if (data.length < length) {
          handleConnectionClosure();
          return;
        }
        processReceivedFrame(data);
        receiveFrameAsync();
      },
      onError: (err) {
        lastError = err as Error;
        protocolError();
      },
      onDone: () {
        handleConnectionClosure();
      },
    );
  }

  void sendFrameAsync(Uint8List frame) {
    Uint8List lengthPrefixedData = Uint8List(frame.length + 4);
    int length = frame.length;
    lengthPrefixedData[0] = length >> 24;
    lengthPrefixedData[1] = length >> 16;
    lengthPrefixedData[2] = length >> 8;
    lengthPrefixedData[3] = length;
    lengthPrefixedData.setRange(4, frame.length + 4, frame);
    connection.add(lengthPrefixedData);
  }

  Future<void> encryptAndSendOfflineFrame(
      LocationNearbyConnections.OfflineFrame frame) async {
    var d2dMsg = DeviceToDeviceMessage();
    serverSeq++;
    d2dMsg.sequenceNumber = serverSeq;
    d2dMsg.message = frame.writeToBuffer();

    List<int> serializedMsg = d2dMsg.writeToBuffer();
    List<int> iv = List.generate(16, (index) => Random.secure().nextInt(256));
    var encryptedData = await AesGcm.with256bits().encrypt(
      serializedMsg,
      secretKey: SecretKey(encryptKey!),
      nonce: iv,
    );

    var hb = HeaderAndBody();
    hb.body = encryptedData.cipherText;
    hb.header = Header();
    hb.header.encryptionScheme = EncScheme.AES_256_CBC;
    hb.header.signatureScheme = SigScheme.HMAC_SHA256;
    hb.header.iv = iv;
    var md = GcmMetadata();
    md.type = Type.DEVICE_TO_DEVICE_MESSAGE;
    md.version = 1;
    hb.header.publicMetadata = md.writeToBuffer();

    var smsg = SecureMessage();
    smsg.headerAndBody = hb.writeToBuffer();
    smsg.signature = (await Hmac.sha256()
            .calculateMac(smsg.headerAndBody, secretKey: sendHmacKey!))
        .bytes;
    sendFrameAsync(smsg.writeToBuffer());
  }

  void sendTransferSetupFrame(SharingNearby.Frame frame) async {
    var transfer = LocationNearbyConnections.PayloadTransferFrame();
    transfer.packetType =
        LocationNearbyConnections.PayloadTransferFrame_PacketType.DATA;
    transfer.payloadChunk.offset = 0 as Int64;
    transfer.payloadChunk.flags = 0;
    transfer.payloadChunk.body = frame.writeToBuffer();
    transfer.payloadHeader.id =
        (Random.secure().nextInt(1 << 63) - (1 << 63)) as Int64;
    transfer.payloadHeader.type = LocationNearbyConnections
        .PayloadTransferFrame_PayloadHeader_PayloadType.BYTES;
    transfer.payloadHeader.totalSize = Int64(transfer.payloadChunk.body.length);
    transfer.payloadHeader.isSensitive = false;

    var wrapper = LocationNearbyConnections.OfflineFrame();
    wrapper.version = LocationNearbyConnections.OfflineFrame_Version.V1;
    wrapper.v1 = LocationNearbyConnections.V1Frame();
    wrapper.v1.type =
        LocationNearbyConnections.V1Frame_FrameType.PAYLOAD_TRANSFER;
    wrapper.v1.payloadTransfer = transfer;
    await encryptAndSendOfflineFrame(wrapper);

    transfer.payloadChunk.flags = 1; // .lastChunk
    transfer.payloadChunk.offset = Int64(transfer.payloadChunk.body.length);
    transfer.payloadChunk.clearBody();
    wrapper.v1.payloadTransfer = transfer;
    await encryptAndSendOfflineFrame(wrapper);
  }

  Future<void> decryptAndProcessReceivedSecureMessage(
      SecureMessage smsg) async {
    if (!smsg.hasSignature() || !smsg.hasHeaderAndBody()) {
      throw NearbyError.requiredFieldMissing;
    }
    var mac = await Hmac.sha256()
        .calculateMac(smsg.headerAndBody, secretKey: recvHmacKey!);
    var hmac = mac.bytes;
    if (hmac != smsg.signature) {
      throw NearbyError.protocolError("hmac!=signature");
    }
    var headerAndBody = HeaderAndBody.fromBuffer(smsg.headerAndBody);
    var decryptedData = Uint8List(headerAndBody.body.length);

    var decryptedLength = 0;
    var status = await AesCbc.with256bits(
      macAlgorithm: AesGcm.aesGcmMac,
      paddingAlgorithm: PaddingAlgorithm.pkcs7,
    ).decrypt(
      SecretBox(headerAndBody.body, nonce: headerAndBody.header.iv, mac: mac),
      secretKey: SecretKey(decryptKey!),
      possibleBuffer: decryptedData,
    );

    if (status.isEmpty) {
      throw Exception("CCCrypt error: $status");
    }
    decryptedData = decryptedData.sublist(0, decryptedLength);
    var d2dMsg = DeviceToDeviceMessage.fromBuffer(decryptedData);
    if (!d2dMsg.hasMessage() || !d2dMsg.hasSequenceNumber()) {
      throw NearbyError.requiredFieldMissing;
    }
    clientSeq += 1;
    if (d2dMsg.sequenceNumber != clientSeq) {
      throw NearbyError.protocolError(
          "Wrong sequence number. Expected $clientSeq, got ${d2dMsg.sequenceNumber}");
    }
    var offlineFrame =
        LocationNearbyConnections.OfflineFrame.fromBuffer(d2dMsg.message);
    if (!offlineFrame.hasV1() || !offlineFrame.v1.hasType()) {
      throw NearbyError.requiredFieldMissing;
    }

    if (offlineFrame.v1.type ==
        LocationNearbyConnections.V1Frame_FrameType.PAYLOAD_TRANSFER) {
      if (!offlineFrame.v1.hasPayloadTransfer()) {
        throw NearbyError.requiredFieldMissing;
      }
      var payloadTransfer = offlineFrame.v1.payloadTransfer;
      var header = payloadTransfer.payloadHeader;
      var chunk = payloadTransfer.payloadChunk;
      if (!header.hasType() || !header.hasId()) {
        throw NearbyError.requiredFieldMissing;
      }
      if (!payloadTransfer.hasPayloadChunk() ||
          !chunk.hasOffset() ||
          !chunk.hasFlags()) {
        throw NearbyError.requiredFieldMissing;
      }
      if (header.type ==
          LocationNearbyConnections
              .PayloadTransferFrame_PayloadHeader_PayloadType.BYTES) {
        var payloadID = header.id.toInt();
        if (header.totalSize > NearbyConnection.SANE_FRAME_LENGTH) {
          payloadBuffers.remove(payloadID);
          throw NearbyError.protocolError(
              "Payload too large (${header.totalSize} bytes)");
        }
        if (payloadBuffers[payloadID] == null) {
          payloadBuffers[payloadID] = Uint8List(header.totalSize.toInt())
              .buffer
              .asByteData() as Uint8List;
        }
        var buffer = payloadBuffers[payloadID]!;
        if (chunk.offset != buffer.lengthInBytes) {
          payloadBuffers.remove(payloadID);
          throw NearbyError.protocolError(
              "Unexpected chunk offset ${chunk.offset}, expected ${buffer.lengthInBytes}");
        }
        if (chunk.hasBody()) {
          buffer.setRange(buffer.lengthInBytes,
              buffer.lengthInBytes + chunk.body.length, chunk.body);
        }
        if ((chunk.flags & 1) == 1) {
          payloadBuffers.remove(payloadID);
          var innerFrame =
              SharingNearby.Frame.fromBuffer(buffer.buffer.asUint8List());
          await processTransferSetupFrame(innerFrame);
        }
      } else if (header.type ==
          LocationNearbyConnections
              .PayloadTransferFrame_PayloadHeader_PayloadType.FILE) {
        await processFileChunk(frame: payloadTransfer);
      }
    } else if (offlineFrame.v1.type ==
        LocationNearbyConnections.V1Frame_FrameType.KEEP_ALIVE) {
      sendKeepAlive(ack: true);
    } else {
      print("Unhandled offline frame encrypted: $offlineFrame");
    }
  }

  static Future<String> pinCodeFromAuthKey(SecretKey key) async {
    var hash = 0;
    var multiplier = 1;
    var keyBytes = await key.extractBytes();

    for (var _byte in keyBytes) {
      var byte = _byte.toSigned(8);
      hash = (hash + byte * multiplier) % 9973;
      multiplier = (multiplier * 31) % 9973;
    }

    return hash.abs().toString().padLeft(4, '0');
  }

  void finalizeKeyExchange(GenericPublicKey peerKey) async {
    if (!peerKey.hasEcP256PublicKey()) {
      throw NearbyError.requiredFieldMissing();
    }

    var domain = ECCurve_secp256r1();
    var clientX = peerKey.ecP256PublicKey.x;
    var clientY = peerKey.ecP256PublicKey.y;
    if (clientX.length > 32) {
      clientX = clientX.sublist(clientX.length - 32);
    }
    if (clientY.length > 32) {
      clientY = clientY.sublist(clientY.length - 32);
    }

    var key = ECPublicKey(
        domain.curve.createPoint(
          BigInt.parse(clientX.toString(), radix: 16),
          BigInt.parse(clientY.toString(), radix: 16),
        ),
        domain);

    var dhs = (key.Q! * privateKey?.d)?.x?.toBigInteger()?.toRadixString(16);
    var derivedSecretKey = HMac.withDigest(Digest("sha256"))
        .process(Uint8List.fromList(dhs!.codeUnits));

    var ukeyInfo = <int>[];
    ukeyInfo.addAll(ukeyClientInitMsgData!);
    ukeyInfo.addAll(ukeyServerInitMsgData!);
    var authString = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(derivedSecretKey),
      nonce: "UKEY2 v1 auth".codeUnits,
      info: ukeyInfo,
    );
    var nextSecret = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(derivedSecretKey),
      nonce: "UKEY2 v1 next".codeUnits,
      info: ukeyInfo,
    );

    pinCode = await NearbyConnection.pinCodeFromAuthKey(
        SecretKey((await authString).bytes));

    var salt = <int>[
      0x82,
      0xAA,
      0x55,
      0xA0,
      0xD3,
      0x97,
      0xF8,
      0x83,
      0x46,
      0xCA,
      0x1C,
      0xEE,
      0x8D,
      0x39,
      0x09,
      0xB9,
      0x5F,
      0x13,
      0xFA,
      0x7D,
      0xEB,
      0x1D,
      0x4A,
      0xB3,
      0x83,
      0x76,
      0xB8,
      0x25,
      0x6D,
      0xA8,
      0x55,
      0x10
    ];

    var d2dClientKey = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey((await nextSecret).bytes),
      nonce: salt,
      info: "client".codeUnits,
    );

    var d2dServerKey = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey((await nextSecret).bytes),
      nonce: salt,
      info: "server".codeUnits,
    );

    var smsgSalt = HMac.withDigest(Digest("sha256"))
        .process(Uint8List.fromList("SecureMessage".codeUnits));

    var clientKey = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey((await d2dClientKey).bytes),
      nonce: smsgSalt,
      info: "ENC:2".codeUnits,
    );
    var clientHmacKey = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey((await d2dClientKey).bytes),
      nonce: smsgSalt,
      info: "SIG:1".codeUnits,
    );
    var serverKey = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey((await d2dServerKey).bytes),
      nonce: smsgSalt,
      info: "ENC:2".codeUnits,
    );
    var serverHmacKey = Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey((await d2dServerKey).bytes),
      nonce: smsgSalt,
      info: "SIG:1".codeUnits,
    );

    if (isServer()) {
      decryptKey = (await serverKey).bytes;
      recvHmacKey = await serverHmacKey;
      encryptKey = (await clientKey).bytes;
      sendHmacKey = await clientHmacKey;
    } else {
      decryptKey = (await clientKey).bytes;
      recvHmacKey = await clientHmacKey;
      encryptKey = (await serverKey).bytes;
      sendHmacKey = await serverHmacKey;
    }
  }

  void disconnect() {
    connection
        .write(null); // Send null content to indicate end of communication
    connection.close(); // Close the socket connection
    connectionClosed = true;
    connection.done.then((_) {
      handleConnectionClosure(); // Handle the connection closure after it is done
    });
  }

  void sendDisconnectionAndDisconnect() async {
    var offlineFrame = LocationNearbyConnections.OfflineFrame();
    offlineFrame.version = LocationNearbyConnections.OfflineFrame_Version.V1;
    offlineFrame.v1.type =
        LocationNearbyConnections.V1Frame_FrameType.DISCONNECTION;
    offlineFrame.v1.disconnection =
        LocationNearbyConnections.DisconnectionFrame();

    if (encryptionDone) {
      await encryptAndSendOfflineFrame(offlineFrame);
    } else {
      sendFrameAsync(offlineFrame.writeToBuffer());
    }
    disconnect();
  }

  void sendUkey2Alert(Ukey2Alert_AlertType type) {
    var alert = Ukey2Alert();
    alert.type = type;
    var msg = Ukey2Message();
    msg.messageType = Ukey2Message_Type.ALERT;
    msg.messageData = alert.writeToBuffer();
    sendFrameAsync(msg.writeToBuffer());
    disconnect();
  }

  Future<void> sendKeepAlive({required bool ack}) async {
    var offlineFrame = LocationNearbyConnections.OfflineFrame();
    offlineFrame.version = LocationNearbyConnections.OfflineFrame_Version.V1;
    offlineFrame.v1.type =
        LocationNearbyConnections.V1Frame_FrameType.KEEP_ALIVE;
    offlineFrame.v1.keepAlive.ack = ack;

    try {
      if (encryptionDone) {
        await encryptAndSendOfflineFrame(offlineFrame);
      } else {
        sendFrameAsync(offlineFrame.writeToBuffer());
      }
    } catch (error) {
      print("Error sending KEEP_ALIVE: $error");
    }
  }
}

class NearbyError implements Exception {
  final String message;

  NearbyError(this.message);

  static NearbyError protocolError(String message) =>
      NearbyError("Protocol error: $message");

  static NearbyError requiredFieldMissing() =>
      NearbyError("Required field missing");

  static NearbyError ukey2() => NearbyError("UKEY2 error");

  static NearbyError inputOutput(int cause) =>
      NearbyError("Input/output error: $cause");
}

class RemoteDeviceInfo {
  final String name;
  final DeviceType type;

  RemoteDeviceInfo(this.name, this.type);
}

enum DeviceType { unknown, phone, tablet, computer }

extension DeviceTypeExtension on DeviceType {
  static DeviceType fromRawValue(int value) {
    switch (value) {
      case 0:
        return DeviceType.unknown;
      case 1:
        return DeviceType.phone;
      case 2:
        return DeviceType.tablet;
      case 3:
        return DeviceType.computer;
      default:
        return DeviceType.unknown;
    }
  }
}

class TransferMetadata {
  final List<FileMetadata> files;

  TransferMetadata(this.files);
}

class FileMetadata {
  final String name;
  final int size;
  final String mimeType;

  FileMetadata(this.name, this.size, this.mimeType);
}

class InternalFileInfo {
  final FileMetadata meta;
  final int payloadID;
  final Uri destinationURL;
  int bytesTransferred = 0;
  RandomAccessFile? fileHandle;
  int? progress;
  bool created = false;

  InternalFileInfo(this.meta, this.payloadID, this.destinationURL);
}
