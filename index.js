var keythereum = require("keythereum");
var sha256 = require("crypto-js/hmac-sha256");
var privateToPublic = require("ethereumjs-util").privateToPublic;

//Config variables (to be passed to the constructor)
var address = ""; //ethereum account address to use, defaults to defaultaccount if string is empty
// address = "4922f48cb953e4193fdf9720900ea7d0f37f7e71"; //Steffens key for local testing
var datadir = ""; //optional, defaults to "/home/currentUser/.ethereum"
var password = "pw0"; //password for unlocking the account
var message = "This is my message.";

function SignService(ethAddress, ethPassword, ethDataDirectory){
    this.ethereumAddress = ethAddress;
    this.ethereumPassword = ethPassword;
    this.ethereumDataDir = ethDataDirectory;
}

SignService.prototype.importEthereumPrivateKey = function(){
    try {   
        var keyObject = keythereum.importFromFile(this.ethereumAddress, this.ethereumDataDir);
        console.log("imported key for address: " + keyObject.address); 
        var privateKey = keythereum.recover(this.ethereumPassword, keyObject);

        console.log("private key fetched successfully");
        
        var publicKey = privateToPublic(privateKey);
        console.log("public key: " + publicKey.toString("hex"));
        console.log("Hash of message '" + message + "': " + sha256(message, publicKey.toString())); // TODO: get the public key somehow and use it instead of the private key!
        return true;
    }
    catch(err){
        console.error("Something went wrong: " + err.message);
        return false; 
    }
}

//export object for later use outside
module.exports = SignService;

//just local for testing the implementation
var service = new SignService(address, password, datadir);
service.importEthereumPrivateKey();