import { getUser, insertUser } from '../db/users.js';
import { user_locations, local_users, servers, serverId } from '../state/tables.js';
import { verifyContentSigUnified } from '../transport/sign.js';
import { broadcastToServers } from '../state/broadcast.js';
import { makeUserAdvertise, makeUserDeliver, makeServerDeliver, makeAck, makeError } from '../transport/envelope.js';
import { publicChannel } from './groupManager.js'

export async function handleUserHello(envelope, websocket) {
  const { payload } = envelope;
  const { user_id, pubkey, privkey_store, pake_password, meta, version } = payload;

  if (!user_id || !pubkey || !privkey_store || !pake_password || !version) {
    return;
  }

  const currentUser = await getUser(user_id);

  if (!currentUser) {
    // New user registration
    await insertUser({ user_id, pubkey, privkey_store, pake_password, meta, version });
    local_users.set(user_id, websocket);
    user_locations.set(user_id, 'local');
    const userAnnouncement = makeUserAdvertise(user_id);
    broadcastToServers(userAnnouncement);
  } else {
    // Existing user login - verify public key
    if (currentUser.pubkey !== pubkey) {
      console.warn(`Public key mismatch for user ${user_id}`);
      return;
    }
    local_users.set(user_id, websocket);
    user_locations.set(user_id, 'local');
    const userAnnouncement = makeUserAdvertise(user_id);
    broadcastToServers(userAnnouncement);
  }
  
  publicChannel(user_id);
  broadcastUserListUpdate();
}

function broadcastUserListUpdate() {
  const userListUpdateMessage = {
    type: 'USER_LIST_UPDATED',
    from: serverId,
    to: 'all_local_users',
    ts: Date.now(),
    payload: {
      message: 'User list updated'
    },
    sig: ''
  };
  
  local_users.forEach((websocket) => {
    if (websocket.readyState === 1) {
      try {
        websocket.send(JSON.stringify(userListUpdateMessage));
      } catch (error) {
        console.error('Broadcast error:', error.message);
      }
    }
  });
}

export async function handleMsgDirect(envelope, websocket) {
  const { from, to, timestamp, payload } = envelope;

  const messageSender = await getUser(from);
  if (!messageSender) {
    const errorResponse = makeError('USER_NOT_FOUND', `Sender ${from} not registered`);
    websocket.send(JSON.stringify(errorResponse));
    return;
  }

  const signatureVerified = await verifyContentSigUnified(payload, messageSender.pubkey, from, to, timestamp);
  if (!signatureVerified) {
    const errorResponse = makeError('INVALID_SIG', `Invalid signature from ${from}`);
    websocket.send(JSON.stringify(errorResponse));
    return;
  }

  const userLocation = user_locations.get(to);
  if (!userLocation) {
    const errorResponse = makeError('USER_NOT_FOUND', `Recipient ${to} not found`);
    websocket.send(JSON.stringify(errorResponse));
    return;
  }

  if (userLocation === 'local') {
    const recipientWebsocket = local_users.get(to);
    if (!recipientWebsocket) {
      const errorResponse = makeError('USER_NOT_FOUND', `Recipient ${to} disconnected`);
      websocket.send(JSON.stringify(errorResponse));
      return;
    }
    envelope.from = serverId;
    envelope.payload.sender = from;
    const deliveryMessage = makeUserDeliver(envelope);
    recipientWebsocket.send(JSON.stringify(deliveryMessage));
  } else {
    const targetServer = servers.get(userLocation);
    if (!targetServer) {
      const errorResponse = makeError('USER_NOT_FOUND', `Server ${userLocation} not connected`);
      websocket.send(JSON.stringify(errorResponse));
      return;
    }
    envelope.from = serverId;
    envelope.to = userLocation;
    envelope.payload.sender = from;
    envelope.payload.user_id = to;
    const deliveryMessage = makeServerDeliver(envelope);
    targetServer.send(JSON.stringify(deliveryMessage));
  }

  const acknowledgment = makeAck(envelope);
  websocket.send(JSON.stringify(acknowledgment));
}

export async function handleGetUsers(envelope, websocket) {
  try {
    const { getAllUsers } = await import('../db/users.js');
    const userList = await getAllUsers();
    
    const userListResponse = {
      type: 'USERS_LIST',
      from: serverId,
      to: envelope.from,
      ts: Date.now(),
      payload: {
        users: userList.map(user => ({
          id: user.user_id,
          name: user.user_id,
          pubkey: user.pubkey,
          version: user.version
        }))
      },
      sig: ''
    };
    
    websocket.send(JSON.stringify(userListResponse));
    
  } catch (error) {
    const errorResponse = makeError('GET_USERS_FAILED', 'Failed to get users');
    websocket.send(JSON.stringify(errorResponse));
  }
}

export async function handleGetPubkey(envelope, websocket) {
  try {
    const { user_id } = envelope.payload;
    
    if (!user_id) {
      const errorResponse = makeError('INVALID_REQUEST', 'Missing user_id parameter');
      websocket.send(JSON.stringify(errorResponse));
      return;
    }
    
    const targetUser = await getUser(user_id);
    
    if (!targetUser) {
      const errorResponse = makeError('USER_NOT_FOUND', `User ${user_id} not found`);
      websocket.send(JSON.stringify(errorResponse));
      return;
    }
    
    const pubkeyResponse = {
      type: 'PUBKEY_RESPONSE',
      from: serverId,
      to: envelope.from,
      ts: Date.now(),
      payload: {
        user_id: targetUser.user_id,
        pubkey: targetUser.pubkey,
        meta: targetUser.meta
      },
      sig: ''
    };
    
    websocket.send(JSON.stringify(pubkeyResponse));
    
  } catch (error) {
    const errorResponse = makeError('GET_PUBKEY_FAILED', 'Failed to get user public key');
    websocket.send(JSON.stringify(errorResponse));
  }
}