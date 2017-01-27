var keythereum = require('keythereum')
var ethUtils = require('ethereumjs-util')

module.exports = {
    /**
     * get the ethereum private key for the specified ethereum account, throws exception in case of any error
     * @param  {String} ethereumAddress         address of the ethereum account or empty if default account
     * @param  {String} ethereumDataDir         absolute path of the ethereum data, defaults to ~/.ethereum
     * @param  {String} ethereumAccountPassword password of the specified ethereum account
     * @return {Buffer}                         Private key of the specified ethereum account
     */
    getPrivateKey: function(ethereumAddress, ethereumDataDir, ethereumAccountPassword, cb){
        if(typeof cb === 'function'){
            try {
                keythereum.importFromFile(ethereumAddress, ethereumDataDir, function(keyObject){
                    keythereum.recover(ethereumAccountPassword, keyObject, function(privateKey){
                        return cb(null, privateKey)
                    })
                })
            } catch (err){
                return cb(err)
            }
        } else {
            try {
                var keyObject = keythereum.importFromFile(ethereumAddress, ethereumDataDir)
                return keythereum.recover(ethereumAccountPassword, keyObject)
            } catch (err){
                return err
            }
        }
    },
    /**
     * get public key for a given ethereum private key
     * @param  {Buffer} privateKey ethereum private key
     * @return {Buffer}            the associated public key
     */
    getPublicKey: function(privateKey, cb){
        if(typeof cb === 'function'){
            try {
                return cb(null, ethUtils.privateToPublic(privateKey))
            }
            catch(err){
                return cb(err)
            }
        } else {
            try {
                return ethUtils.privateToPublic(privateKey)
            }
            catch(err){
                return err
            }
        }
    },
    /**
     * sign a message hashed with sha3 (256 bit) using the ethereum private key
     * @param  {String} message    The message to sign
     * @param  {Buffer} privateKey The ethereum private key used to sign the message
     * @return {Object}            Signature object with the keys v(Buffer), r(Buffer) and s(Number) inside
     */
	sign:function(message, privateKey, cb)
	{
        if(typeof cb === 'function'){
            try {
                return cb(null, ethUtils.ecsign(ethUtils.sha3(message), privateKey))
            } catch (err){
                return cb(err)
            }
        }
        else {
            try {
                return ethUtils.ecsign(ethUtils.sha3(message), privateKey)
            } catch(err){
                return err
            }
        }
	},
    /**
     * verify signature of the message by recovering the public key, comparing it to the provided one
     * @param  {String} message   message that was signed
     * @param  {Number} v         Signature parameter
     * @param  {Buffer} r         Signature parameter
     * @param  {Buffer} s         Signature parameter
     * @param  {Buffer} publicKey public key of the message sender
     * @return {Boolean}          true, if public keys match, otherwise false.
     */
	verify: function(message, v, r, s, publicKey, cb)
	{
        if(typeof cb === 'function'){
            try {
                return cb(null, publicKey.toString('hex') === ethUtils.ecrecover(ethUtils.sha3(message), v, r, s).toString('hex'))
            } catch (err){
                return cb(err)
            }
        } else {
            try {
    		  return publicKey.toString('hex') === ethUtils.ecrecover(ethUtils.sha3(message), v, r, s).toString('hex')
            }
            catch (err){
                return err
            }
        }
	}
};
