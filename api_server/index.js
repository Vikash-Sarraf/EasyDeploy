require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const bp = require('body-parser');
const CryptoJS = require('crypto-js');
const { Parser } = require('json2csv');
const compression = require('compression');
const jwt = require('jsonwebtoken');
const Redis = require('ioredis');
const fs = require('fs');
const path = require('path')

const app = express();
app.use(cors());
app.use(bp.json());
app.use(compression())

const redisClient = new Redis(process.env.REDIS_URI);


const PORT = process.env.PORT || 5000;

let tokenExpiry = 0;
let cachedToken = null;

const convertVariables = function(templateContent, variables) {
    if (!templateContent || !variables) return templateContent || '';
    return templateContent.replace(/{{(.*?)}}/g, (_, variableName) => variables[variableName] || '');
};

const signableContent = function(request, variables) {
    if (!request.url) {
        console.error("ERROR: Missing request URL", request);
        throw new Error("Invalid request object: URL missing");
    }

    const requestPath = convertVariables(request.url.trim(), variables).replace(/^https?:\/\/[^\/]+\//, '/');
    const params = [
        request.method,
        requestPath,
        request.headers?.['content-type'] || '',
        request.headers?.['content-md5'] || '',
        convertVariables(request.headers?.['nep-organization'] || '', variables)
    ];
    return params.filter(Boolean).join('\n');
};

const calculateSignature = function(request, secretKey, sharedKey) {
    const date = new Date();
    const key = secretKey + date.toISOString().slice(0, 19) + '.000Z';
    const sc = signableContent(request, { 'nep-organization': request.headers['nep-organization'] });
    const hmac = CryptoJS.HmacSHA512(sc, key);
    return `AccessKey ${sharedKey}:${CryptoJS.enc.Base64.stringify(hmac)}`;
};

const getAuthToken = async (org) => {
    const now = Date.now();
    if (cachedToken && now < tokenExpiry) {
        //console.log("Using cached token");
        return cachedToken;
    }

    console.log("Fetching new token...");
    const date = new Date().toUTCString();
    const authorization = calculateSignature({
        method: 'POST',
        url: 'https://gateway-staging.ncrcloud.com/security/authentication/login',
        headers: { 'content-type': 'application/json', 'nep-organization': org }
    }, process.env.BSP_SECRET_KEY, process.env.BSP_SHARED_KEY);

    const options = {
        method: 'POST',
        url: 'https://gateway-staging.ncrcloud.com/security/authentication/login',
        headers: {
            'Content-Type': 'application/json',
            'nep-organization': org,
            'Authorization': authorization,
            'Date': date,
            'User-Agent': 'axios/1.8.3',
            'Accept-Encoding': 'gzip, compress, deflate, br',
        },
        data: ''
    };

    try {
        const resp = await axios.request(options);
        cachedToken = resp.data.token;
        tokenExpiry = jwt.decode(cachedToken).exp * 1000;
        return cachedToken;
    } catch (error) {
        console.error("Error fetching auth token:", error.response?.data || error.message);
        throw new Error("Authentication failed");
    }
};

const getDepartmentName = async (merchandiseId, org, token) => {
    const cacheKey = `department_name:${merchandiseId}`;
    const cacheDepName = await redisClient.get(cacheKey);
    if (cacheDepName) {
        return cacheDepName;
    }
    const departmentConfig = {
        method: 'get',
        url: `https://gateway-staging.ncrcloud.com/catalog/v2/category-nodes/${merchandiseId}`,
        headers: {
            'nep-organization': org,
            'Accept': '*/*',
            'Authorization': `Bearer ${token}`
        }
    };

    try {
        const depName = (await axios.request(departmentConfig)).data.title.values[0].value;
        await redisClient.set(cacheKey, depName, 'EX', 24*60*60)

        return depName;
    } catch (error) {
        console.error(`Error fetching department ${merchandiseId}:`, error.response?.data || error.message);
        return "Unknown Department";
    }
};

const refreshESLDetails = async (org, unit) => {
    try {
        const token = await getAuthToken(org);

        const itemDetailsConfig = {
            method: 'get',
            url: 'https://gateway-staging.ncrcloud.com/catalog/v2/item-details/search',
            headers: {
                'nep-organization': org,
                'nep-enterprise-unit': unit,
                'Accept': '*/*',
                'Authorization': `Bearer ${token}`
            },
        };

        const itemDetails = (await axios.request(itemDetailsConfig)).data.pageContent || [];

        const departmentPromises = itemDetails.map(async (itemObj) => {
            try {
                const cacheKey = `item:${itemObj.item.itemId.itemCode}:${org}:${unit}`;
                const cacheItem = await redisClient.get(cacheKey);
                if (!cacheItem || cacheItem !== JSON.stringify(itemObj)) {
                    await redisClient.set(cacheKey, JSON.stringify(itemObj), "EX", process.env.REFRESH_RATE);
                    const item = itemObj.item;
                    const itemPrice = (itemObj && Array.isArray(itemObj.itemPrices) && itemObj.itemPrices.length > 0) 
                        ? itemObj.itemPrices.find(obj => obj.status === "ACTIVE") || {} 
                        : {};

                    const itemAttributes = itemObj.itemAttributes;
                    const merchandiseId = item.merchandiseCategory?.nodeId;

                    const depName = merchandiseId ? await getDepartmentName(merchandiseId, org, token) : "Unknown Department";

                    return {
                        itemCode: item.itemId.itemCode,
                        LongDescription: item.longDescription.values?.[0]?.value || '',
                        ShortDescription: item.shortDescription.values?.[0]?.value || '',
                        Manufacturer: item.manufacturerCode || '',
                        DepartmentId: item.departmentId || '',
                        DepartmentName: depName,
                        UOM: itemPrice?.dynamicAttributes?.[0]?.attributes?.find(obj => obj.key == 'UOM')?.value || '',
                        UnitSize: itemPrice?.dynamicAttributes?.[0]?.attributes?.find(obj => obj.key == 'UNITS')?.value || '',
                        onSaleFlag: item.status || '',
                        Tax1Flag: itemAttributes?.groups?.some(obj => obj.groupCode == "Tax1") || false,
                        changedOn: item.auditTrail?.lastUpdated || '',
                        Price: itemPrice?.price || '',
                        Currency: itemPrice?.currency || '',
                    };
                }
                return null; 
            } catch (error) {
                console.error("Error processing item:", error.message);
                return null;
            }
        });

        const esl_details = (await Promise.allSettled(departmentPromises))
            .filter(p => p.status === "fulfilled" && p.value !== null)
            .map(p => p.value);

        console.log(`Processed ${esl_details.length} ESL details`);

        if (esl_details.length === 0) {
            console.log("No new or updated ESL details found");
            return "No new or updated ESL details found";
        }

        const fields = [
            'itemCode', 'LongDescription', 'ShortDescription', 'Manufacturer', 'DepartmentId', 'DepartmentName',
            'UOM', 'UnitSize', 'onSaleFlag', 'Tax1Flag', 'changedOn', 'Price', 'Currency'
        ];
        const parser = new Parser({ fields });
        const csv = parser.parse(esl_details);
        console.log("CSV generated successfully");
        //console.log(esl_details)
        const filePath = path.join(__dirname, 'esl_details.csv');
        fs.writeFileSync(filePath, csv);
        console.log("CSV generated successfully");
        return filePath;

    } catch (error) {
        console.error("Error fetching ESL details:", error);
        return "Error fetching details";
    }
};

app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

app.get('ready', (req, res) => {
    const isReady = true;
    if (isReady) {
        res.status(200).send('Ready');
    } else {
        res.status(500).send('Not Ready');
    }
})

app.post('/subscription-notification', async (req, res) => {
    try {
        const filePath = await refreshESLDetails(process.env.ORG, process.env.UNIT);
        console.log(filePath);
        if (filePath === "Error fetching details") {
            res.status(500).send('Error during refresh');
        } else if (filePath === "No new or updated ESL details found") {
            res.status(200).send(filePath);
        } else {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename="esl_details.csv"');
            fs.createReadStream(filePath).pipe(res)
        }
    } catch (e) {
        res.status(500).send('Error during refresh');
        console.log(e);
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
