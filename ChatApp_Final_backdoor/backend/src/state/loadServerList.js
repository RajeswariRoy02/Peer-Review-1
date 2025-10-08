// src/state/loadServerList.js

import fs from 'fs';
import path from 'path';
import WebSocket from 'ws';
import { serverId } from './tables.js';
import { server_addrs, servers } from './tables.js';
import { makeServerAnnounce } from '../transport/envelope.js';

export function loadServerList(filePath) {
  const fullPath = path.resolve(filePath);
  const raw = fs.readFileSync(fullPath, 'utf-8');
  const allServers = JSON.parse(raw);

  for (const entry of allServers) {
    const { host, port, server_id } = entry;
    if (!host || !port || !server_id) continue;

    server_addrs.set(server_id, [host, port]);
    console.log(`Server id ${server_id} init`);

    // console.log(`Target server_id: ${server_id} My serverId: ${serverId}`)
    if (server_id === serverId) continue;

    const url = `ws://${host}:${port}`;
    const ws = new WebSocket(url);

    ws.on('open', () => {
      console.log(`[LINKED] Connected to ${server_id} (${url})`);
      servers.set(server_id, ws);

      const msg = makeServerAnnounce();
      ws.send(JSON.stringify(msg));
    });

    ws.on('error', (err) => {
      console.warn(`[ERROR] Failed to connect to ${server_id}: ${err.message}`);
    });

    ws.on('close', () => {
      console.log(`[CLOSED] Connection to ${server_id} closed`);
      servers.delete(server_id);
    });
  }
}
