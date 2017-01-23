var keythereum = require("keythereum");
var ethUtils = require("ethereumjs-util");

module.exports = {
    /**
     * get the ethereum private key for the specified ethereum account, throws exception in case of any error
     * @param  {String} ethereumAddress         address of the ethereum account or empty if default account
     * @param  {String} ethereumDataDir         absolute path of the ethereum data, defaults to ~/.ethereum
     * @param  {String} ethereumAccountPassword password of the specified ethereum account
     * @return {Buffer}                         Private key of the specified ethereum account
     */
    getPrivateKey: function(ethereumAddress, ethereumDataDir, ethereumAccountPassword){
        try {
            var keyObject = keythereum.importFromFile(ethereumAddress, ethereumDataDir);
            return keythereum.recover(ethereumAccountPassword, keyObject);
        }
        catch (err){
            throw err;
        }
    },
    getPublicKey: function(privateKey){
        try {
            return ethUtils.privateToPublic(privateKey);
        }
        catch(err){
            throw err;
        }
    },
    /**
     * sign a message hashed with sha3 (256 bit) using the ethereum private key
     * @param  {String} message    The message to sign
     * @param  {Buffer} privateKey The ethereum private key used to sign the message
     * @return {Object}            Signature object with the keys v(Buffer), r(Buffer) and s(Number) inside
     */
	sign:function(message, privateKey)
	{
        try {
    		var hashedMessage = ethUtils.sha3(message);
            return ethUtils.ecsign(hashedMessage, privateKey);
        }
        catch(err){
            throw err;
        }
	},
    /**
     * verify signature of the message by recovering the public key, comparing it to the provided one
     * @param  {String} message   message that was signed
     * @param  {Buffer} v         Signature parameter
     * @param  {Buffer} r         Signature parameter
     * @param  {Number} s         Signature parameter
     * @param  {Buffer} publicKey public key of the message sender
     * @return {Boolean}          true, if public keys match, otherwise false.
     */
	verify: function(message, v, r, s, publicKey)
	{
        try {
		  return publicKey.toString("hex") === ethUtils.ecrecover(ethUtils.sha3(message), v, r, s).toString("hex");
        }
        catch (err){
            throw err;
        }
	}
};