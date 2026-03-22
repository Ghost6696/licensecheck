const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');

const shop = 'shrine-demo.myshopify.com';
const privateKey = fs.readFileSync(path.join(__dirname, 'private.pem'), 'utf8');

// 1. Generate signature (license)
const sign = crypto.createSign('SHA256');
sign.update(shop);
const signature = sign.sign(privateKey);
const license = signature.toString('base64');

console.log('Testing license validation for:', shop);
console.log('License length (Base64):', license.length);

// 2. Test API
const options = {
    hostname: 'localhost',
    port: 3000,
    path: `/api/updates/check?shop=${encodeURIComponent(shop)}&license=${encodeURIComponent(license)}`,
    method: 'GET'
};

const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => {
        console.log('Response Status:', res.statusCode);
        console.log('Response Body:', data);
        const json = JSON.parse(data);
        if (json.status === 'active') {
            console.log('\n✅ TEST PASSED: License is ACTIVE');
        } else {
            console.log('\n❌ TEST FAILED: License is', json.status);
            process.exit(1);
        }
    });
});

req.on('error', (e) => {
    console.error('API Request failed:', e.message);
    process.exit(1);
});

req.end();
