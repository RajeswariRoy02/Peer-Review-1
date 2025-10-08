// src/protocol/groupManager.js
import crypto from 'crypto';
import { getAllUsers } from '../db/users.js';
import { makePublicChannelAdd, makePublicChannelUpdate, makeEnvelope } from '../transport/envelope.js';
import { local_users, serverId } from '../state/tables.js';
import { broadcastToServers } from '../state/broadcast.js';

export async function generateGroupKey() {
  const newGroupKey = crypto.randomBytes(32);

  const allUsers = await getAllUsers();
  const keyWrappingList = [];

  for (const currentUser of allUsers) {
    try {
      // Ensure public key is in PEM format
      let publicKey = currentUser.pubkey;
      if (!publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
        // If not in PEM format, try to convert from base64
        try {
          publicKey = `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----`;
        } catch (error) {
          console.warn(`[WARN] Invalid pubkey format for ${currentUser.user_id}`);
          continue;
        }
      }

      const encryptedKey = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        newGroupKey
      );

      keyWrappingList.push({
        member_id: currentUser.user_id,
        wrapped_key: encryptedKey.toString('base64url')
      });
    } catch (error) {
      console.warn(`[WARN] Failed to wrap group key for ${currentUser.user_id}: ${error.message}`);
    }
  }

  console.log('[GROUP_KEY] Generated new group key and wrapped for', keyWrappingList.length, 'users');
  return { groupKey: newGroupKey.toString('base64url'), wrappedList: keyWrappingList };
}

export async function publicChannel(userId) {

  const { wrappedList } = await generateGroupKey();

  if (userId != null) {
    const addChannelEnvelope = makePublicChannelAdd(userId);
    broadcastToServers(addChannelEnvelope);
    console.log(`[PUBLIC_CHANNEL] Broadcasted ADD for ${userId}`);
  }

  const updateChannelEnvelope = makePublicChannelUpdate(wrappedList);
  broadcastToServers(updateChannelEnvelope);
  console.log(`[PUBLIC_CHANNEL] Broadcasted UPDATED with ${wrappedList.length} wrapped keys`);

  pushWrappedKeysToLocalUsers(wrappedList);
  console.log(`[PUBLIC_CHANNEL] Completed send keys to local users`);
}

export function pushWrappedKeysToLocalUsers(wrappedList) {
  for (const keyEntry of wrappedList) {
    const { member_id, wrapped_key } = keyEntry;

    const userWebsocket = local_users.get(member_id);
    if (userWebsocket && userWebsocket.readyState === 1) {
      const keyEnvelope = makeEnvelope('PUBLIC_CHANNEL_KEY', {
        wrapped_key
      });

      keyEnvelope.from = serverId;
      keyEnvelope.to = member_id;

      userWebsocket.send(JSON.stringify(keyEnvelope));
      console.log(`[PUBLIC_CHANNEL] Sent wrapped key to local user ${member_id}`);
    }
  }
}