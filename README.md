Signing Module
==============

A small module providing signing and verification of messages for the Cloud Prototyping Microservices Marketplace

## Instalation
```shell
npm install cp2017sign --save
```

## Usage
```javascript
var cp2017sign=require('cp2017sign');

//get the private key of your ethereum account
var privateKey = cp2017sign.getPrivateKey(ethereumAddress, ethereumDataDir, ethereumAccountPassword);

//sign message
var signedMessage = cp2017sign.sign("Test message", privateKey);

//get public key (just for comparison in this example)
var publicKey = cp2017sign.getPublicKey(privateKey);

//verify signature of the message
var result = cp2017sign.verify("Test message", signedMessage.v, signedMessage.r, signedMessage.s, publicKey);
console.log("Verification result: " + result);
```
## Release History

* 0.1.0 Initial release
