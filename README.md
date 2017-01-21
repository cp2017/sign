Signing Module
==============

A small module providing signing and verification of messages for the CLoud Prototyping Microservices Marketplace

## Instalation
npm install cp2017sign --save

## Usage

var cp2017sign=require('cp2017sign');
//Signing a message
var hash=cp2017sign.sign(messageBody, publicKey);
//Verification of a signed message
var verified=cp2017sign.verify(messageBody, publicKey, messageHash);

## Release History

* 0.1.0 Initial release
