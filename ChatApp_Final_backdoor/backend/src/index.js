import { WebSocketServer } from 'ws';
import { init } from './state/init.js';
import { setServerInfo, local_users } from './state/tables.js';
import { handleServerAnnounce, handleUserAdvertise, handleUserRemove, handleServerDeliver, handlePublicChannelUpdate, handleMsgPublicChannel, handleMsgFile, handleMsgFileInit, handleMsgFileChunk, handleMsgFileComplete } from './protocol/serverHandlers.js';
import { handleUserHello, handleMsgDirect, handleGetUsers, handleGetPubkey } from './protocol/userHandlers.js';
import { makeUserRemove } from './transport/envelope.js';
import { broadcastToServers } from './state/broadcast.js';
import { v4 as uuidv4 } from 'uuid';

const currentServerId = `server-${uuidv4()}`;
const database = init();
const serverPort = process.env.PORT || 8080;

setServerInfo({ host: 'localhost', port: serverPort, server_id: currentServerId });
const webSocketServer = new WebSocketServer({ port: serverPort });

console.log(`Chat System Server ${currentServerId} running on ws://localhost:${serverPort}`);

const messageHandlers = {
  'USER_HELLO': handleUserHello,
  'GET_USERS': handleGetUsers,
  'GET_PUBKEY': handleGetPubkey,
  'USER_REMOVE': handleUserRemove,
  'SERVER_ANNOUNCE': handleServerAnnounce,
  'USER_ADVERTISE': handleUserAdvertise,
  'MSG_DIRECT': handleMsgDirect,
  'SERVER_DELIVER': handleServerDeliver,
  'PUBLIC_CHANNEL_UPDATED': handlePublicChannelUpdate,
  'MSG_PUBLIC_CHANNEL': handleMsgPublicChannel,
  'MSG_FILE': handleMsgFile,
  'MSG_FILE_INIT': handleMsgFileInit,
  'MSG_FILE_CHUNK': handleMsgFileChunk,
  'MSG_FILE_COMPLETE': handleMsgFileComplete
};

webSocketServer.on('connection', (websocket) => {
  websocket.on('message', async (messageString) => {
    try {
      const messageEnvelope = JSON.parse(messageString);
      const messageHandler = messageHandlers[messageEnvelope.type];
      
      if (messageHandler) {
        await messageHandler(messageEnvelope, websocket);
      } else {
        console.warn('Unknown message type:', messageEnvelope.type);
      }
    } catch (error) {
      console.error('Message handling error:', error.message);
    }
  });

  websocket.on('close', () => {
    for (const [userId, userSocket] of local_users.entries()) {
      if (userSocket === websocket) {
        local_users.delete(userId);
        const removeMessage = makeUserRemove(userId);
        broadcastToServers(removeMessage);
        break;
      }
    }
  });
});
