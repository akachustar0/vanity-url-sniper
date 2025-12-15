const WebSocket = require('ws');
const tls = require('tls');
const extractJson = require('extract-json-string');
const fs = require('fs');
const dns = require('dns');
const { constants: cryptoConstants } = require('crypto');
const config = {
  token: "token",
  serverid: "svid"
};
let guilds = {};
let lastSeq = null;
let hbInterval = null;
let mfaToken = null;
let mfaTokenLastChecked = 0;
let lastMfaFileTime = 0;

const connectionPool = new Map();
const MAX_POOL_SIZE = 10;
const POOL_ENDPOINTS = [
  'canary.discord.com:443'
];
const TLS_OPTIONS = {
  host: "canary.discord.com",
  port: 443,
  minVersion: "TLSv1.3",
  maxVersion: "TLSv1.3",
  servername: "canary.discord.com",
  rejectUnauthorized: false,
  ALPNProtocols: ["http/1.1"],
  ciphers: "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
  ecdhCurve: "X25519",
  honorCipherOrder: true,
  secureOptions: cryptoConstants.SSL_OP_NO_SSLv2 | cryptoConstants.SSL_OP_NO_SSLv3 | cryptoConstants.SSL_OP_NO_TLSv1 | cryptoConstants.SSL_OP_NO_TLSv1_1,
  requestOCSP: false,
  enableTrace: false,
  keepAlive: true,
  keepAliveInitialDelay: 0,
  handshakeTimeout: 300,
  highWaterMark: 2 * 1024 * 1024
};
function safeExtract(data) {
  if (typeof data !== "string") {
    try {
      return JSON.stringify(data);
    } catch (e) {
      return null;
    }
  }
  try {
    return extractJson.extract(data);
  } catch (e) {
    return null;
  }
}
function readMfaToken(force = false) {
  const now = Date.now();
  try {
    const stats = fs.statSync('mfa_token.txt');
    if (mfaToken && stats.mtimeMs <= lastMfaFileTime && !force) {
      return mfaToken;
    }
    lastMfaFileTime = stats.mtimeMs;
    let token = fs.readFileSync('mfa_token.txt', 'utf8').trim();
    if (token) {
      if (token !== mfaToken) {
        mfaToken = token;
        console.log(`MFA Read`);
      } else {
        mfaToken = token;
      }
      mfaTokenLastChecked = now;
      return mfaToken;
    }
  } catch (e) {}
  return mfaToken;
}
async function req(method, path, body = null) {
  return new Promise(resolve => {
    const availableEndpoints = POOL_ENDPOINTS.filter(endpoint => {
      const socket = connectionPool.get(endpoint);
      return socket && !socket.destroyed;
    });
    
    let poolKey = availableEndpoints.length > 0 
      ? availableEndpoints[Math.floor(Math.random() * availableEndpoints.length)]
      : POOL_ENDPOINTS[Math.floor(Math.random() * POOL_ENDPOINTS.length)];
    
    let socket = connectionPool.get(poolKey);
    
    if (socket && !socket.destroyed) {
      sendRequest(socket);
    } else {
      if (connectionPool.size >= MAX_POOL_SIZE) {
        const oldestKey = connectionPool.keys().next().value;
        const oldSocket = connectionPool.get(oldestKey);
        if (oldSocket && !oldSocket.destroyed) oldSocket.destroy();
        connectionPool.delete(oldestKey);
      }
      
      const [host, port] = poolKey.split(':');
      const options = { ...TLS_OPTIONS, host, port: parseInt(port) };
      
      socket = tls.connect(options, () => {
        socket.setNoDelay(true);
        socket.setKeepAlive(true, 1000);
        connectionPool.set(poolKey, socket);
        sendRequest(socket);
      });
    }
    
    function sendRequest(sock) {
      const headers = [
        `${method} ${path} HTTP/1.1`,
        'Host: canary.discord.com',
        `Authorization: ${config.token}`,
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'X-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJ0ci1UUiIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEzMy4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEzMy4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vIiwicmVmZXJyaW5nX2RvbWFpbiI6Ind3dy5nb29nbGUuY29tIiwic2VhcmNoX2VuZ2luZSI6Imdvb2dsZSIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNTYxNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImhhc19jbGllbnRfbW9kcyI6ZmFsc2V9'
      ];
      
      if (mfaToken) headers.push(`X-Discord-MFA-Authorization: ${mfaToken}`);
      if (body) headers.push('Content-Type: application/json', `Content-Length: ${Buffer.byteLength(body)}`);
      headers.push('Connection: keep-alive', '', body || '');
      sock.write(headers.join('\r\n'));
      
      sock.on('data', () => {});
      sock.on('end', () => resolve('{}'));
      sock.on('error', () => {
        resolve('{}'); 
        connectionPool.delete(poolKey);
        sock.destroy();
      });
    }
    
    socket.on('error', (err) => {
      if (err.code === 'ECONNRESET') {
        connectionPool.delete(poolKey);
        setTimeout(() => req(method, path, body).then(resolve), 100);
        return;
      }
      resolve('{}');
    });
    socket.setTimeout(800, () => {
      resolve('{}');
      connectionPool.delete(poolKey);
      socket.destroy();
    });
  });
}

function connect() {
  req("GET", "/api/v0/gateway").then(res => {
    let url;
    try {
      url = JSON.parse(res)?.url;
    } catch (e) {
      const extracted = safeExtract(res);
      if (extracted) {
        try {
          url = JSON.parse(extracted)?.url;
        } catch (e) {}
      }
    }
    let gw = url || "wss://gateway-us-east1-b.discord.gg/?v=10&encoding=json";
    try {
      gw = gw.replace("wss://gateway.discord.gg", "wss://gateway-us-east1-b.discord.gg");
    } catch (e) {}
    try {
      gw = gw.replace("v=9", "v=10");
    } catch (e) {}
    const ws = new WebSocket(gw, {
      perMessageDeflate: false,
      handshakeTimeout: 200,
      maxPayload: 64 * 1024 * 1024,
      skipUTF8Validation: true,
      followRedirects: false,
      maxRedirects: 0
    });
    
    ws.on("open", () => ws.send(JSON.stringify({
      op: 2,
      d: {
        token: config.token,
        intents: 1,
        properties: {
          os: "Windows",
          browser: "la neye bakiyon la anayin ami la",
          device: "Desktop"
        }
      }
    })));
    
    ws.on("message", async messageData => {
      try {
        let payload;
        try {
          payload = typeof messageData === 'string' ? JSON.parse(messageData) : JSON.parse(messageData.toString());
        } catch (e) {
          const jsonString = safeExtract(messageData.toString());
          if (jsonString) {
            payload = JSON.parse(jsonString);
          } else {
            return;
          }
        }
        if (payload.s) lastSeq = payload.s;
        if (payload.op === 10) {
          clearInterval(hbInterval);
          hbInterval = setInterval(() => ws.send(JSON.stringify({ op: 1, d: lastSeq })), payload.d.heartbeat_interval);
        }
        
        if (payload.t === "READY") {
          payload.d.guilds.filter(g => g.vanity_url_code).forEach(g => {
            guilds[g.id] = g.vanity_url_code;
          });
          console.log(`${JSON.stringify(guilds)}`);
        }
        
        if (payload.t === "GUILD_UPDATE") {
          const guildId = payload.d.id || payload.d.guild_id;
          const oldVanity = guilds[guildId];
          const newVanity = payload.d.vanity_url_code;
          if (oldVanity && oldVanity !== newVanity) {
            readMfaToken();
            if (mfaToken) {
              const requests = [];
              for (let i = 0; i < 10; i++) {
                requests.push(req("PATCH", `/api/v7/guilds/${config.serverid}/vanity-url`, JSON.stringify({ code: oldVanity })));
              }
              await Promise.all(requests);
            }
          }
          if (newVanity) {
            guilds[guildId] = newVanity;
          } else if (guilds[guildId]) {
            delete guilds[guildId];
          }
        }
      } catch (e) {}
    });
    
    ws.on("close", () => {
      clearInterval(hbInterval);
      setTimeout(connect, 5000);
    });
    ws.on("error", () => ws.close());
  }).catch(() => setTimeout(connect, 5000));
}

(async () => {
  readMfaToken(true);
  dns.resolve4('canary.discord.com', (err, addresses) => {
    if (!err && addresses[0]) {
      TLS_OPTIONS.host = addresses[0];
      console.log(`socket listener ip : ${addresses[0]}`);
    }
  });
  connect();
  setInterval(() => readMfaToken(false), 30000);
})();
process.on('uncaughtException', () => {});
