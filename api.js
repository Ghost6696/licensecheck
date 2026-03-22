const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const publicKey = fs.readFileSync(path.join(__dirname, 'public.pem'), 'utf8');

// The endpoint Shrine theme uses
app.all('/api/updates/check', (req, res) => {
    // Shrine theme usually sends parameters in the query for GET or body for POST
    const license = req.query.license || req.body.license;
    const shop = req.query.shop || req.body.shop;

    if (!license || !shop) {
        return res.status(400).json({ status: 'inactive', message: 'Missing license or shop parameter.' });
    }

    try {
        // Decode the Base64 license
        const signature = Buffer.from(license, 'base64');
        
        // The data we verify is the shop domain (same as in generator.js)
        const verify = crypto.createVerify('SHA256');
        verify.update(shop);
        const isValid = verify.verify(publicKey, signature);

        if (isValid) {
            console.log(`[SUCCESS] Validated license for: ${shop}`);
            // Return active status (Shrine expects this structure)
            return res.json({
                status: 'active',
                message: 'Shrine Theme License: ACTIVE',
                details: {
                    shop: shop,
                    authenticated: true
                }
            });
        } else {
            console.log(`[FAILED] Invalid license for: ${shop}`);
            return res.json({ status: 'inactive', message: 'License key is invalid for this domain.' });
        }
    } catch (error) {
        console.error('Validation error:', error);
        return res.status(500).json({ status: 'error', message: 'Internal server error during validation.' });
    }
});

app.listen(PORT, () => {
    console.log(`\nShrine Auther API running on port ${PORT}`);
    console.log(`Endpoint: http://localhost:${PORT}/api/updates/check\n`);
});
