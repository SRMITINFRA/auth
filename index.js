const express = require('express');
const bodyParser = require('body-parser');
const radius = require('node-radius');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// RADIUS server details
const RADIUS_SERVER = '192.168.15.254';  // Your RADIUS server IP
const RADIUS_SECRET = 'your_radius_shared_secret';
const FIREBOX_SHARED_SECRET = 'your_firebox_shared_secret';

// Root Route
app.get('/', (req, res) => {
    res.send('Hello! Use the /auth endpoint to authenticate.');
});

// Authentication Route
app.post('/auth', (req, res) => {
    const { username, password, ts, sn, mac, redirect } = req.body;

    // RADIUS Authentication
    authenticateWithRadius(username, password)
        .then(success => {
            const success_value = success ? 1 : 0;
            const sess_timeout = success ? 1200 : 0;
            const idle_timeout = success ? 600 : 0;

            // Generate signature using SHA1
            const signature = generateSignature(ts, sn, mac, success_value, sess_timeout, idle_timeout);

            // Construct the access decision URL
            const decisionUrl = `http://10.10.0.1:4106/wgcgi.cgi?action=hotspot_auth&ts=${ts}&success=${success_value}&sess_timeout=${sess_timeout}&idle_timeout=${idle_timeout}&sig=${signature}&redirect=${encodeURIComponent(redirect)}`;

            // Redirect to Firebox
            res.redirect(decisionUrl);
        })
        .catch(err => {
            console.error('Error authenticating with RADIUS:', err);
            res.status(500).send('Authentication Failed');
        });
});

// Function to authenticate user using RADIUS
function authenticateWithRadius(username, password) {
    return new Promise((resolve, reject) => {
        const client = radius.createClient({
            host: RADIUS_SERVER,
            port: 1812,
            timeout: 5000,
            retries: 3
        });

        const packet = client.createPacket({
            code: 'Access-Request',
            secret: RADIUS_SECRET,
            identifier: 0,
            attributes: [
                ['User-Name', username],
                ['User-Password', password]
            ]
        });

        client.send(packet, (err, response) => {
            if (err) {
                return reject(err);
            }

            if (response.code === 'Access-Accept') {
                resolve(true);  // Successful authentication
            } else {
                resolve(false);  // Failed authentication
            }
        });
    });
}

// Function to generate SHA1 signature
function generateSignature(ts, sn, mac, success, sess_timeout, idle_timeout) {
    const data = `${ts}${sn}${mac}${success}${sess_timeout}${idle_timeout}${FIREBOX_SHARED_SECRET}`;
    return crypto.createHash('sha1').update(data).digest('hex');
}

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
