const express = require('express')
const express_jwt = require('express-jwt');
const UnauthorizedError = require('express-jwt/lib/errors/UnauthorizedError');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');


function b64EncodeUnicode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
        return String.fromCharCode('0x' + p1);
    }));
}

function b64DecodeUnicode(str) {
    return decodeURIComponent(Array.prototype.map.call(Buffer.from(str, 'base64').toString('binary'), function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

function addNewLines(str) {
    var finalString = '';
    for(var i=0; i < str.length; i++) {
        finalString += str.substring(0, 64) + '\n';
        str = str.substring(64);
    }
    finalString += str;

    return finalString;
}

function removeLines(pem) {
    var lines = pem.split('\n');
    var encodedString = '';
    for(var i=0; i < lines.length; i++) {
        encodedString += lines[i].trim();
    }
    return encodedString;
}

function stringToArrayBuffer(byteString){
    var byteArray = new Uint8Array(byteString.length);
    for(var i=0; i < byteString.length; i++) {
        byteArray[i] = byteString.codePointAt(i);
    }
    return byteArray;
}

function  arrayBufferToString(exportedPrivateKey){
    var byteArray = new Uint8Array(exportedPrivateKey);
    var byteString = '';
    for(var i=0; i < byteArray.byteLength; i++) {
        byteString += String.fromCodePoint(byteArray[i]);
    }
    return byteString;
}


function valid_token_binding() {
    var middleware = async function(req, res, next) {


        if (req.headers && req.headers.authorization) {
            var token = "";

            var parts = req.headers.authorization.split(' ');
            if (parts.length == 2) {
                var scheme = parts[0];
                var credentials = parts[1];

                if (/^Bearer$/i.test(scheme)) {
                    token = credentials;
                } else {
                    if (credentialsRequired) {
                        return next(new UnauthorizedError('credentials_bad_scheme', { message: 'Format is Authorization: Bearer [token]' }));
                    } else {
                        return next();
                    }
                }
            } else {
                return next(new UnauthorizedError('credentials_bad_format', { message: 'Format is Authorization: Bearer [token]' }));
            }

            const dtoken = jwt.decode(token, { complete: true }) || {};

            console.log('signature incomming', req.headers.signature);
            const signature = stringToArrayBuffer(b64DecodeUnicode(req.headers.signature));
            if (!signature) {
                return next(new UnauthorizedError('signature_required', { message: 'No signature header was found' }));
            }


            const pubKey = Buffer.from(dtoken.payload.pubKey, 'base64');

            // const result = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', dtoken.payload.pubKey, signature, 'poc-something');
            const verify = crypto.createVerify('SHA256');
            verify.write('poc-something');
            verify.end();
            result = verify.verify(pubKey, signature);

            if (!result) {
                return next(new UnauthorizedError('token biding invalid', { message: 'signature does not match with public key' }));
            }

            return next();
        }
    }

    return middleware;
}

const app = express()
const port = 3000

app.set('json spaces', 40);


app.get('/', (req, res) => res.send('Hello World!<br> \n Open <a href="client">client.html</a>, which will get a token from this server,<br> \n by posting pubKey to <a href="auth">auth</a>!'))

app.get('/client', (req, res) => res.sendFile(__dirname + '/client.html'));

app.post('/auth', (req, res) => {
    if (!req.header('pubKey')) {
        console.log('please provide `pubKey` in the header, with public key when authenticating');
        return res.send('please provide `pubKey` in the header, with public key when authenticating!')
    }

    console.log('auth request', req.header('pubKey'));

    const token = jwt.sign({ user: 'poc',  pubKey: req.header('pubKey')}, 'poc_secret');


    return res.send({ token: token });
});

app.get('/resource',
    express_jwt({secret: 'poc_secret'}),
    valid_token_binding(),
    (req, res) => {

        console.log('returning resource');

        return res.send({result: 'Valuable resource after valid token, bounded to signature'})
    }
);


app.listen(port, () => console.log(`Example app listening on port ${port}!`))

