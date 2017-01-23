var keythereum = require("keythereum");
var ethUtils = require("ethereumjs-util");

//Config variables (to be passed to the constructor)
var address = ""; //ethereum account address to use, defaults to defaultaccount if string is empty
 address = "4922f48cb953e4193fdf9720900ea7d0f37f7e71"; //Steffens key for local testing
var datadir = ""; //optional, defaults to "/home/currentUser/.ethereum"
var password = "pw0"; //password for unlocking the account
var message = "This is my message.";
var publicKey;

function SignService(ethAddress, ethPassword, ethDataDirectory){
    this.ethereumAddress = ethAddress;
    this.ethereumPassword = ethPassword;
    this.ethereumDataDir = ethDataDirectory;
}

SignService.prototype.sign = function(){
    try {   
        var keyObject = keythereum.importFromFile(this.ethereumAddress, this.ethereumDataDir);
        console.log("imported key for address: " + keyObject.address); 
        var privateKey = keythereum.recover(this.ethereumPassword, keyObject);
        console.log("private key fetched successfully");
        publicKey = ethUtils.privateToPublic(privateKey);
        var hashedMessage = ethUtils.sha3(message);
        console.log("hashed message: " + hashedMessage.toString("hex"));
        var signedMessage = ethUtils.ecsign(hashedMessage, privateKey);
        console.log("signed message: ");
        console.log(signedMessage);
        return signedMessage;
    }
    catch(err){
        console.error("Something went wrong: " + err.message);
        return false; 
    }
}

SignService.prototype.verify = function(signedMessage){
    var pubKeyRecovered = ethUtils.ecrecover(ethUtils.sha3(message), signedMessage.v, signedMessage.r, signedMessage.s);
    console.log("recovered public key: " + pubKeyRecovered.toString("hex"));
    console.log("expected public key: " + publicKey.toString("hex"));
    return pubKeyRecovered.toString("hex") === publicKey.toString("hex");
}

//export object for later use outside
module.exports = SignService;

//just local for testing the implementation
var service = new SignService(address, password, datadir);
var signedMessage = service.sign();
if(signedMessage != false){
    var result = service.verify(signedMessage);
    console.log("Signature verified. Result: " + result);
}