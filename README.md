Signing Module
==============

A small module providing signing and verification of messages for the Cloud Prototyping Microservices Marketplace

## Installation
```shell
npm install cp2017sign
```

## Usage
```javascript
var cp2017sign = require('cp2017sign')

//get the private key of your ethereum account
var privateKey = cp2017sign.getPrivateKey(ethereumAddress, ethereumDataDir, ethereumAccountPassword)

//sign message
var signedMessage = cp2017sign.sign("Test message", privateKey)

//get public key (just for comparison in this example)
var publicKey = cp2017sign.getPublicKey(privateKey)

/* verify signature of the message (deprecated since version 1.1.0)
var result = cp2017sign.verify("Test message", signedMessage.v, signedMessage.r, signedMessage.s, publicKey)
*/

//new since version 1.1.0: easier verification by just handing over one signature object
signedMessage.publicKey = publicKey
result = cp2017sign.verifySignature("Test message", signedMessage)

console.log("Verification result: " + result)
```

## Asynchronous usage
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

## Utility functions
The following functions can be used to encode your signature information into a base64-String and recover that string into an object:

Encoding:
```javascript
var signature = cp2017sign.sign(message, privateKey)

var encodedSignatureString = cp2017sign.signatureToBase64String(signature, publicKey, bufferEncoding, callback)
```
This function encodes the signature + public key (needed for verifying the signature) into one string. 'bufferEncoding' and 'callback' are optional parameters. 

The bufferEncoding parameter defines the encoding used for the conversion of all buffers in the signature object into strings.
This way it is easier for the message receiver to recover the object from the base64-encoded string.
If an invalid encoding or no encoding is provided, it will default to 'hex'.

Decoding:
```javascript
var recoveredSignatureObject = cp2017sign.signatureFromBase64String(encodedSignatureString, bufferEncoding, callback)
```
In this function the process of the encoding is reverted, returning an object containing the required properties 'v', 'r' and 's' or an Error object if not all of them are contained.
Optionally, if the encoded object contained the public key, it will also be contained in the result.
The 'bufferEncoding' and 'callback' parameter are optional as in the encoding function.

## Release History

* 0.1.0 Initial release
* 1.0.0 Include signature and verification of public and private Ethereum keys
* 1.0.1 Update readme
* 1.0.2 Update readme
* 1.0.3 Fixed wrong parameter types in the verify function