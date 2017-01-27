Signing Module
==============

A small module providing signing and verification of messages for the Cloud Prototyping Microservices Marketplace

## Installation
```shell
npm install cp2017sign
```

## Usage
```javascript
var cp2017sign = require('cp2017sign');

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

Every function has an optional callback parameter for asynchronous use.
The first parameter is always an error object (or null, if there was no error) and the second parameter is the actual method result (or null, if there was an error).

Example:

```javascript
cp2017sign.sign(yourMessage, privateKey, function(error, result){
  if(error){
    //handle the error
  } else {
    //handle the result
  }
})
```
## Release History

* 0.1.0 Initial release
* 1.0.0 Include signature and verification of public and private Ethereum keys
* 1.0.1 Update readme
* 1.0.2 Update readme
* 1.0.3 Fixed wrong parameter types in the verify function