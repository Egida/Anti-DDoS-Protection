const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const helmet = require('helmet');
const gradient = require('gradient-string');
const titles = require('console-title');

// Define your configuration constants
const MAX_REQUESTS_PER_SECOND = 10;
const MAX_CONNECTIONS_PER_IP = 20;
const BAN_TIME = 60 * 1000;
const IP_BAN_MAP = new Map();
const IP_REQUEST_MAP = new Map();
const BLOCKED_USER_AGENTS = new Set(); // Use a Set to store blocked user agents
const BLACKLISTED_IPS = new Set(); // Define BLACKLISTED_IPS

const LOCAL_IP = '127.0.0.1';
const SSL_CERTIFICATE_PATH = 'cert.pem'; 
const SSL_PRIVATE_KEY_PATH = 'private-key.pem'; 

// Read the IP addresses to block from the block_setting.txt file
const blockSettingFile = 'block_setting.txt';
fs.readFile(blockSettingFile, 'utf8', (err, data) => {
  if (err) {
    console.error(`Error reading block_setting.txt file: ${err}`);
    return;
  }
  const ipsToBlock = data.split('\n');
  ipsToBlock.forEach((ip) => {
    ip = ip.trim();
    if (ip) {
      BLACKLISTED_IPS.add(ip);
    }
  });
  console.log(`Blocked IPs: ${Array.from(BLACKLISTED_IPS).join(', ')}`);
});

// Create a rate limiter to handle request rate limiting
const rateLimiter = new RateLimiterMemory({
  points: MAX_REQUESTS_PER_SECOND,
  duration: 1, // 1 second
});

const ACCESS_LOG_PATH = 'access-logs.txt';
const USER_ACTIVITY_LOG_PATH = 'user-activity-logs.txt';
const CONNECTION_LOG_PATH = 'connection-logs.txt';

function logUserActivity(clientIP, requestPath, userAgent) {
  const logMessage = `User ${clientIP} accessed ${requestPath} using ${userAgent}\n`;
  fs.appendFile(USER_ACTIVITY_LOG_PATH, logMessage, (err) => {
    if (err) {
      console.error(`Error writing to user activity log file: ${err}`);
    }
  });
}

function logConnection(clientIP) {
  const logMessage = `Connection from IP => ${clientIP}\n`;
  fs.appendFile(CONNECTION_LOG_PATH, logMessage, (err) => {
    if (err) {
      console.error(`Error writing to connection log file: ${err}`);
    }
  });
}

// Function to dynamically block user agents
function blockUserAgent(userAgent) {
  if (userAgent && (userAgent.toLowerCase().includes('ddos') || userAgent.toLowerCase().includes('thread'))) {
    BLOCKED_USER_AGENTS.add(userAgent);
    console.log(`Blocked User-Agent (${userAgent})`);
  }
}

// Function to handle flood protection
function handleFloodProtection(clientIP, res) {
  if (isLocalConnection(clientIP)) {
    // Exclude local connections from flood protection
    return false;
  }

  const currentTime = Date.now();
  const recentRequests = IP_REQUEST_MAP.get(clientIP) || [];

  // Remove requests older than BAN_TIME
  IP_REQUEST_MAP.set(
    clientIP,
    recentRequests.filter((requestTime) => currentTime - requestTime <= BAN_TIME)
  );

  // Check if the number of recent requests exceeds the threshold
  if (recentRequests.length >= MAX_REQUESTS_PER_SECOND) {
    console.log(`Banned IP (${clientIP}) due to flood requests`);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return true;
  }

  // Add the current request time to the list
  recentRequests.push(currentTime);
  IP_REQUEST_MAP.set(clientIP, recentRequests);

  return false;
}

// Create an HTTPS server with SSL certificate and private key
const httpsOptions = {
  cert: fs.readFileSync(SSL_CERTIFICATE_PATH),
  key: fs.readFileSync(SSL_PRIVATE_KEY_PATH),
};

const httpsServer = https.createServer(httpsOptions, (req, res) => {
  const clientIP = req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'];
  const requestPath = req.url;

  if (!isLocalConnection(clientIP)) {
    logUserActivity(clientIP, requestPath, userAgent);
    logConnection(clientIP);
  }

  blockUserAgent(userAgent);

  if (BLOCKED_USER_AGENTS.has(userAgent) || handleFloodProtection(clientIP, res)) {
    return;
  }

  const currentTime = Date.now();

  rateLimiter.consume(clientIP)
    .then(() => {
      if (requestPath.includes('botnet-like-pattern')) {
        console.log(`Blocked potential botnet-like request from ${clientIP}`);
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
      }

      const filePath = path.join(__dirname, 'index.html');
      fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
          console.error(`Error reading HTML file: ${err}`);
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(data);
        }
      });
    })
    .catch(() => {
      console.log(`Rate limited request from ${clientIP}`);
      res.writeHead(429, { 'Content-Type': 'text/plain' });
      res.end('Too Many Requests');
    });
});

// Create an HTTP server for port 80 to redirect to HTTPS
const httpServer = http.createServer((req, res) => {
  // Redirect HTTP requests to HTTPS
  const httpsUrl = `https://${req.headers.host}${req.url}`;
  res.writeHead(301, { Location: httpsUrl });
  res.end();
});

const HTTPS_PORT = 443;
const HTTP_PORT = 80;

console.clear();

httpsServer.listen(HTTPS_PORT, () => {
  console.log(`HTTPS Server is running on port ${HTTPS_PORT}`);
});

httpServer.listen(HTTP_PORT, () => {
  console.log(`HTTP Server (redirecting to HTTPS) is running on port ${HTTP_PORT}`);
});

httpServer.on('error', (err) => {
  console.error('HTTP Server Error: ', err);
});

console.log(gradient.mind(`
         {+} Server is Online {+} 
`));

function isLocalConnection(clientIP) {
  return clientIP === LOCAL_IP;
                }
