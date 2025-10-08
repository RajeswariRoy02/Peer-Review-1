import { server_pubkeys, user_locations, server_addrs, servers, serverId, local_users } from '../state/tables.js';
import { makeServerAnnounce, makeUserDeliver, makeFileDeliver, makeMsgPublicChannel, makeAck, makeError } from '../transport/envelope.js';
import { verifySignature, verifyContentSig, verifyFileSig, verifyChunkSig } from '../transport/sign.js';
import { pushWrappedKeysToLocalUsers } from './groupManager.js'
import { broadcastToServers } from '../state/broadcast.js';
import { getUser } from '../db/users.js';
import WebSocket from 'ws';

export function handleServerAnnounce(envelope) {
  const serverFrom = envelope.from;
  const serverPayload = envelope.payload;

  if (!serverFrom || !serverPayload?.host || !serverPayload?.port || !serverPayload?.pubkey) {
    return;
  }

  server_pubkeys.set(serverFrom, serverPayload.pubkey);
  server_addrs.set(serverFrom, [serverPayload.host, serverPayload.port]);

  if (!servers.has(serverFrom) && serverFrom !== serverId) {
    const serverUrl = `ws://${serverPayload.host}:${serverPayload.port}`;
    const newWebsocket = new WebSocket(serverUrl);

    newWebsocket.on('open', () => {
      servers.set(serverFrom, newWebsocket);
      const announcementMessage = makeServerAnnounce();
      newWebsocket.send(JSON.stringify(announcementMessage));
    });

    newWebsocket.on('error', (error) => {
      console.error(`Connection error to ${serverFrom}:`, error.message);
    });

    newWebsocket.on('close', () => {
      servers.delete(serverFrom);
    });
  }
}

export function handleUserAdvertise(envelope, websocket) {
  const { from, payload, sig } = envelope;
  const publicKey = server_pubkeys.get(from);

  if (!verifyEnvelope(from, publicKey, payload, sig)) return;

  const { user_id, server_id } = payload;
  if (!user_id || !server_id) return;

  user_locations.set(user_id, server_id);
}

export function handleUserRemove(envelope, websocket) {
  const { from, payload, sig } = envelope;
  const publicKey = server_pubkeys.get(from);

  if (!verifyEnvelope(from, publicKey, payload, sig)) return;

  const { user_id } = payload;
  if (!user_id) return;

  user_locations.delete(user_id);
}

export function handleServerDeliver(envelope, websocket) {
  const { from, payload, sig } = envelope;
  const publicKey = server_pubkeys.get(from);

  if (!verifyEnvelope(from, publicKey, payload, sig)) return;

  const { user_id } = payload;
  if (!user_id) return;

  const recipientWebsocket = local_users.get(user_id);
  if (!recipientWebsocket) return;

  envelope.to = user_id
  const deliveryMessage = makeUserDeliver(envelope);
  recipientWebsocket.send(JSON.stringify(deliveryMessage));
}

export function handlePublicChannelUpdate(envelope, websocket) {
  const { from, payload, sig } = envelope;
  const publicKey = server_pubkeys.get(from);

  if (!verifyEnvelope(from, publicKey, payload, sig)) return;

  const { wraps } = payload;
  if (!wraps) return;

  pushWrappedKeysToLocalUsers(wraps);
}

export function handleMsgPublicChannel(envelope, websocket) {
  const { from, payload, timestamp } = envelope;

  const channelMessage = makeMsgPublicChannel(payload);
  channelMessage.ts = timestamp;
  channelMessage.from = from;
  channelMessage.to = 'public';
  
  for (const [user_id, userWebsocket] of local_users.entries()) {
    if (userWebsocket && userWebsocket.readyState === 1 && user_id != channelMessage.from) {
      userWebsocket.send(JSON.stringify(channelMessage));
    }
  }

  if (local_users.has(from)) {
    broadcastToServers(channelMessage);
  }
}

function verifyEnvelope(from, publicKey, payload, signature) {
  if (!publicKey) return false;
  if (!verifySignature(payload, signature, publicKey)) return false;
  return true;
}

export async function handleMsgFile(envelope, ws) {
  const { from, to, ts, payload } = envelope;

  const sender = await getUser(from);
  if (!sender) {
    const err = makeError('USER_NOT_FOUND', `Sender ${from} not registered`);
    ws.send(JSON.stringify(err));
    return;
  }

  const verified = await verifyFileSig(payload, sender.pubkey, from, to, ts);
  if (!verified) {
    console.warn(`File signature verification failed for ${from}`);
  }

  if (to === 'public') {
    const publicFileMsg = {
      type: "FILE_DELIVER",
      from: serverId,
      to: "public",
      ts: ts,
      payload: {
        ...payload,
        sender: from,
        channel: "public"
      }
    };
    
    for (const [user_id, userWs] of local_users.entries()) {
      if (userWs && userWs.readyState === 1 && user_id !== from) {
        userWs.send(JSON.stringify(publicFileMsg));
      }
    }
    
    if (local_users.has(from)) {
      broadcastToServers(publicFileMsg);
    }
    
    const ack = makeAck(envelope);
    ws.send(JSON.stringify(ack));
    return;
  }

  const loc = user_locations.get(to);
  if (!loc) {
    const err = makeError('USER_NOT_FOUND', `Recipient ${to} not found`);
    ws.send(JSON.stringify(err));
    return;
  }

  if (loc === 'local') {
    const recvWs = local_users.get(to);
    if (!recvWs) {
      const err = makeError('USER_NOT_FOUND', `Recipient ${to} disconnected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.payload.sender = from;
    const deliver = makeFileDeliver(envelope);
    recvWs.send(JSON.stringify(deliver));
  } else {
    const srv = servers.get(loc);
    if (!srv) {
      const err = makeError('USER_NOT_FOUND', `Server ${loc} not connected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.to = loc;
    envelope.payload.sender = from;
    envelope.payload.user_id = to;
    const deliver = makeFileDeliver(envelope);
    srv.send(JSON.stringify(deliver));
  }

  const ack = makeAck(envelope);
  ws.send(JSON.stringify(ack));
}

export async function handleMsgFileInit(envelope, ws) {
  const { from, to, ts, payload } = envelope;

  const sender = await getUser(from);
  if (!sender) {
    const err = makeError('USER_NOT_FOUND', `Sender ${from} not registered`);
    ws.send(JSON.stringify(err));
    return;
  }

  if (to === 'public') {
    const publicFileInitMsg = {
      type: "FILE_DELIVER",
      from: serverId,
      to: "public",
      ts: ts,
      payload: {
        ...payload,
        sender: from,
        channel: "public"
      }
    };
    
    for (const [user_id, userWs] of local_users.entries()) {
      if (userWs && userWs.readyState === 1 && user_id !== from) {
        userWs.send(JSON.stringify(publicFileInitMsg));
      }
    }
    
    if (local_users.has(from)) {
      broadcastToServers(publicFileInitMsg);
    }
    
    const ack = makeAck(envelope);
    ws.send(JSON.stringify(ack));
    return;
  }

  const loc = user_locations.get(to);
  if (!loc) {
    const err = makeError('USER_NOT_FOUND', `Recipient ${to} not found`);
    ws.send(JSON.stringify(err));
    return;
  }

  if (loc === 'local') {
    const recvWs = local_users.get(to);
    if (!recvWs) {
      const err = makeError('USER_NOT_FOUND', `Recipient ${to} disconnected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.payload.sender = from;
    const deliver = makeFileDeliver(envelope);
    recvWs.send(JSON.stringify(deliver));
  } else {
    const srv = servers.get(loc);
    if (!srv) {
      const err = makeError('USER_NOT_FOUND', `Server ${loc} not connected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.to = loc;
    envelope.payload.sender = from;
    envelope.payload.user_id = to;
    const deliver = makeFileDeliver(envelope);
    srv.send(JSON.stringify(deliver));
  }

  const ack = makeAck(envelope);
  ws.send(JSON.stringify(ack));
}

export async function handleMsgFileChunk(envelope, ws) {
  const { from, to, ts, payload } = envelope;

  const sender = await getUser(from);
  if (!sender) {
    const err = makeError('USER_NOT_FOUND', `Sender ${from} not registered`);
    ws.send(JSON.stringify(err));
    return;
  }

  const verified = await verifyChunkSig(payload, sender.pubkey, from, to, ts);
  if (!verified) {
    console.warn(`Chunk signature verification failed for ${from}`);
  }

  if (to === 'public') {
    const publicFileChunkMsg = {
      type: "MSG_FILE_CHUNK",
      from: serverId,
      to: "public",
      ts: ts,
      payload: {
        ...payload,
        sender: from,
        channel: "public"
      }
    };
    
    for (const [user_id, userWs] of local_users.entries()) {
      if (userWs && userWs.readyState === 1 && user_id !== from) {
        userWs.send(JSON.stringify(publicFileChunkMsg));
      }
    }
    
    if (local_users.has(from)) {
      broadcastToServers(publicFileChunkMsg);
    }
    
    const ack = makeAck(envelope);
    ws.send(JSON.stringify(ack));
    return;
  }

  const loc = user_locations.get(to);
  if (!loc) {
    const err = makeError('USER_NOT_FOUND', `Recipient ${to} not found`);
    ws.send(JSON.stringify(err));
    return;
  }

  if (loc === 'local') {
    const recvWs = local_users.get(to);
    if (!recvWs) {
      const err = makeError('USER_NOT_FOUND', `Recipient ${to} disconnected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.payload.sender = from;
    recvWs.send(JSON.stringify(envelope));
  } else {
    const srv = servers.get(loc);
    if (!srv) {
      const err = makeError('USER_NOT_FOUND', `Server ${loc} not connected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.to = loc;
    envelope.payload.sender = from;
    envelope.payload.user_id = to;
    srv.send(JSON.stringify(envelope));
  }

  const ack = makeAck(envelope);
  ws.send(JSON.stringify(ack));
}

export async function handleMsgFileComplete(envelope, ws) {
  const { from, to, ts, payload } = envelope;

  const sender = await getUser(from);
  if (!sender) {
    const err = makeError('USER_NOT_FOUND', `Sender ${from} not registered`);
    ws.send(JSON.stringify(err));
    return;
  }

  if (to === 'public') {
    const publicFileCompleteMsg = {
      type: "FILE_COMPLETE",
      from: serverId,
      to: "public",
      ts: ts,
      payload: {
        ...payload,
        sender: from,
        channel: "public"
      }
    };
    
    for (const [user_id, userWs] of local_users.entries()) {
      if (userWs && userWs.readyState === 1 && user_id !== from) {
        userWs.send(JSON.stringify(publicFileCompleteMsg));
      }
    }
    
    if (local_users.has(from)) {
      broadcastToServers(publicFileCompleteMsg);
    }
    
    const ack = makeAck(envelope);
    ws.send(JSON.stringify(ack));
    return;
  }

  const loc = user_locations.get(to);
  if (!loc) {
    const err = makeError('USER_NOT_FOUND', `Recipient ${to} not found`);
    ws.send(JSON.stringify(err));
    return;
  }

  if (loc === 'local') {
    const recvWs = local_users.get(to);
    if (!recvWs) {
      const err = makeError('USER_NOT_FOUND', `Recipient ${to} disconnected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.payload.sender = from;
    const deliver = makeUserDeliver(envelope);
    recvWs.send(JSON.stringify(deliver));
  } else {
    const srv = servers.get(loc);
    if (!srv) {
      const err = makeError('USER_NOT_FOUND', `Server ${loc} not connected`);
      ws.send(JSON.stringify(err));
      return;
    }
    envelope.from = serverId;
    envelope.to = loc;
    envelope.payload.sender = from;
    envelope.payload.user_id = to;
    const deliver = makeServerDeliver(envelope);
    srv.send(JSON.stringify(deliver));
  }

  const ack = makeAck(envelope);
  ws.send(JSON.stringify(ack));
}