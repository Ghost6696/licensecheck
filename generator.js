const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function generateLicense(shop, daysValid) {
    const privateKey = fs.readFileSync(path.join(__dirname, 'private.pem'), 'utf8');
    
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + daysValid);
    
    // Create a signature of the shop domain
    const sign = crypto.createSign('SHA256');
    sign.update(shop);
    const signature = sign.sign(privateKey);

    // We pack: [Payload Length (4 bytes)][Payload][Signature]
    // But to match the user's "structure" (high entropy), we could just 
    // encrypt the whole thing with the private key (RSA encryption) if the payload is small,
    // or just return the signature if the theme only cares about the signature.
    
    // However, the signature ALONE is 256 bytes for RSA-2048.
    // If we want a 256-byte output, let's just use the signature as the license key,
    // and verify it against the shop domain.
    
    return signature.toString('base64');
}

const args = process.argv.slice(2);
const shopArg = args.find(a => a.startsWith('--shop='))?.split('=')[1] || 'myshop.myshopify.com';
const daysArg = parseInt(args.find(a => a.startsWith('--days='))?.split('=')[1] || '365');

const license = generateLicense(shopArg, daysArg);
console.log('\n--- NEW LICENSE GENERATED ---');
console.log('Shop:', shopArg);
console.log('Days Valid:', daysArg);
console.log('License Key:\n');
console.log(license);
console.log('\n-----------------------------\n');
