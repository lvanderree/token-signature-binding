webcrypto token binding POC

run:
```bash
npm install
node index.js
``` 


open http://localhost:3000/client in your browser

and look in the console-inspector of your browser

- private/public key pair gets generated
- signing is tested locally in browser
- public key is send to server during auth
- jwt is send back to client, with (bound) pub-key
- client can get resource, with jwt and signing of shared secret

TODO: add something to secret to avoid replay attacks
