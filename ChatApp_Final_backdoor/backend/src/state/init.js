import fs from 'fs';
import path from 'path';
import { setServerKeys } from './tables.js';
import { loadServerList } from './loadServerList.js';
import { initDB } from '../db/init.js';
import { publicChannel } from '../protocol/groupManager.js'

export async function init() {
  const priv = fs.readFileSync(path.resolve('server_priv.pem'), 'utf8');
  const pub = fs.readFileSync(path.resolve('server_pub.pem'), 'utf8');
  setServerKeys(priv, pub);

  const db = await initDB();

  loadServerList(path.resolve('server_list.json'));

  publicChannel(null);

  return db;
}