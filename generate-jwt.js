const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Your Partner ID from the dashboard
const PARTNER_ID = 'd4d4049f-3321-4e6a-8f87-fc3b52008bc9';

// Path to your private key (adjust if needed)
const privateKeyPath = path.join(process.env.HOME, 'Desktop/private.key');
// If the key is in the current directory, use:
// const privateKeyPath = './private.key';

try {
    // Load your private key
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    // Generate the JWT payload
    const payload = {
        sub: PARTNER_ID,
        iss: PARTNER_ID,
        aud: 'moca-network',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour expiry
    };

    // Sign the JWT
    const token = jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        header: {
            kid: PARTNER_ID
        }
    });

    console.log('\n✅ Partner JWT generated successfully!\n');
    console.log('Token:', token);
    console.log('\nExpires:', new Date((Math.floor(Date.now() / 1000) + 3600) * 1000).toISOString());
    console.log('\nUse this token in the x-partner-auth header.\n');

} catch (error) {
    console.error('❌ Error generating JWT:');
    console.error(error.message);
    console.log('\nMake sure:');
    console.log('1. Your private.key exists at:', privateKeyPath);
    console.log('2. The PARTNER_ID is correct');
    console.log('3. You have the jsonwebtoken package installed');
}
