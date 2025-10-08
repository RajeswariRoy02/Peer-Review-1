import { servers } from './tables.js';

export function broadcastToServers(envelope) {
  const messageString = JSON.stringify(envelope);
  for (const [serverId, websocket] of servers) {
    if (websocket.readyState === 1) {
      websocket.send(messageString);
    }
  }
}
