var keythereum = require("keythereum");

//Config variables (to be passed to the constructor)
var address = ""; //ethereum account address to use, defaults to defaultaccount if string is empty
// address = "4922f48cb953e4193fdf9720900ea7d0f37f7e71"; //Steffens key for local testing
var datadir = ""; //optional, defaults to "/home/currentUser/.ethereum"
var password = "pw0"; //password for unlocking the account

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
        return true;
    }
    catch(err){
        console.error("failed fetching the private key: " + err.message);
        return false;
    }
}

//export object for later use outside
module.exports = SignService;

//just local for testing the implementation
var service = new SignService(address, password, datadir);
service.importEthereumPrivateKey();