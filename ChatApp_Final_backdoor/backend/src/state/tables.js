export const servers = new Map();
export const server_addrs = new Map();
export const server_pubkeys = new Map();
export const local_users = new Map();
export const user_locations = new Map();

export let serverPrivKey = null;
export let serverPubKey = null;
export let serverId = null;
export let serverHost = null;
export let serverPort = null;

export function setServerKeys(privateKey, publicKey) {
  serverPrivKey = privateKey;
  serverPubKey = publicKey;
}

export function setServerInfo({ host, port, server_id }) {
  serverHost = host;
  serverPort = port;
  serverId = server_id;
}