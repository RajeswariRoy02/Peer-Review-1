// src/transport/envelope.js

import { signPayload, toBase64Url } from './sign.js';
import { serverId, serverPubKey, serverHost, serverPort } from '../state/tables.js';

export function makeEnvelope(messageType, messagePayload, recipient = '*') {
  return {
    type: messageType,
    from: serverId,
    to: recipient,
    ts: Date.now(),
    payload: messagePayload,
    sig: signPayload(messagePayload)
  };
}

export function makeServerAnnounce() {
  const base64urlPublicKey = pemToBase64Url(serverPubKey);
  const serverPayload = { host: serverHost, port: serverPort, pubkey: base64urlPublicKey };
  return makeEnvelope('SERVER_ANNOUNCE', serverPayload);
}

export function makeUserAdvertise(userId) {
  const userPayload = { user_id: userId, server_id: serverId };
  return makeEnvelope('USER_ADVERTISE', userPayload);
}

export function makeUserRemove(userId) {
  const userPayload = { user_id: userId, server_id: serverId };
  return makeEnvelope('USER_REMOVE', userPayload);
}

export function makeUserDeliver(directMessageEnvelope) {
  directMessageEnvelope.sig = signPayload(directMessageEnvelope.payload);
  directMessageEnvelope.type = 'USER_DELIVER';
  return directMessageEnvelope;
}

export function makeServerDeliver(directMessageEnvelope) {
  directMessageEnvelope.sig = signPayload(directMessageEnvelope.payload);
  directMessageEnvelope.type = 'SERVER_DELIVER';
  return directMessageEnvelope;
}

export function makeFileDeliver(directMessageEnvelope) {
  directMessageEnvelope.sig = signPayload(directMessageEnvelope.payload);
  directMessageEnvelope.type = 'FILE_DELIVER';
  return directMessageEnvelope;
}

export function makePublicChannelAdd(userId) {
  const channelPayload = { add: userId, if_version: 1 };
  return makeEnvelope('PUBLIC_CHANNEL_ADD', channelPayload);
}

let publicChannelVersion = 0;
export function makePublicChannelUpdate(wrappedKeyList) {
  publicChannelVersion++;
  const channelPayload = { wraps: wrappedKeyList, version: publicChannelVersion };
  return makeEnvelope('PUBLIC_CHANNEL_UPDATED', channelPayload);
}

export function makeMsgPublicChannel(messagePayload) {
  return makeEnvelope('MSG_PUBLIC_CHANNEL', messagePayload);
}

export function makeAck(directMessageEnvelope) {
  const ackPayload = { msg_ref: directMessageEnvelope.ts };
  return makeEnvelope('ACK', ackPayload);
}

export function makeError(errorCode, errorDetail) {
  const errorPayload = { code: errorCode, detail: errorDetail };
  return makeEnvelope('ERROR', errorPayload);
}

function pemToBase64Url(pemString) {
  const base64String = pemString
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '');
  return toBase64Url(Buffer.from(base64String, 'base64'));
}
