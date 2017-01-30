var keythereum = require('keythereum')
var ethUtils = require('ethereumjs-util')
var DEFAULT_ENCODING = 'hex'

var getEncodingOrDefault = function(encoding){
    if(Buffer.isEncoding(encoding)){
        return encoding
    } else {
        return DEFAULT_ENCODING
    }
}

var isFunction = function(func){
    if(typeof func === 'function'){
        return true
    } else {
        return false
    }
}

module.exports = {
    /**
     * get the ethereum private key for the specified ethereum account, throws exception in case of any error
     * @param  {String} ethereumAddress         address of the ethereum account or empty if default account
     * @param  {String} ethereumDataDir         absolute path of the ethereum data, defaults to ~/.ethereum
     * @param  {String} ethereumAccountPassword password of the specified ethereum account
     * @return {Buffer}                         Private key of the specified ethereum account
     */
    getPrivateKey: function(ethereumAddress, ethereumDataDir, ethereumAccountPassword, cb = null){
        if(isFunction(cb)){
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
    getPublicKey: function(privateKey, cb = null){
        if(isFunction(cb)){
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
	sign:function(message, privateKey, cb = null)
	{
        if(isFunction(cb)){
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
	verify: function(message, v, r, s, publicKey, cb = null)
	{
        var result = false
        try {
            if(ethUtils.isValidSignature(v,r,s) && ethUtils.isValidPublic(publicKey) && publicKey.toString('hex') === ethUtils.ecrecover(ethUtils.sha3(message), v, r, s).toString('hex')){
                result = true
            }
        } catch(err){
            result = false
        }
        if(isFunction(cb)){
            return cb(null, result)
        } else {
            return result
        }
	},
    /**
     * verify signature easier handing over the complete signature object containing v, r, s and the public key in one object
     * @param  {String}   message         message to verify
     * @param  {Object}   signatureObject Signature object. must contain v (Number), r, s, publicKey (all buffers)
     * @param  {Function} cb              callback function (optional)
     * @return {boolean}                  true, if signature and public key are valid, otherwise false
     */
    verifySignature: function(message, signatureObject, cb = null){
        return module.exports.verify(message, signatureObject.v, signatureObject.r, signatureObject.s, signatureObject.publicKey, cb)
    },
    /**
     * check all elements in the given object (depth 1) for buffers, and if so,
     * replace the entry by an encoded string. If the encoding is invalid or empty,
     * it defaults to 'hex'
     * @param  {Object}   object   objects with buffers to replace
     * @param  {String}   encoding (optional) encoding to be applied to the buffers, or null for default value 'hex'
     * @param  {Function} cb       (optional) callback function
     * @return {Object}            new object where all buffers of the input object are converted to strings using the provided encoding
     */
    convertBuffersToStrings: function(object, encoding, cb = null) {
        var convertedObj = {}
        encoding = getEncodingOrDefault(encoding)
        for(var key in object){
            if(Buffer.isBuffer(object[key])){
                convertedObj[key] = object[key].toString(encoding)
            } else {
                convertedObj[key] = object[key]
            }
        }
        if(isFunction(cb)){
            return cb(null, convertedObj)   
        } else {
            return convertedObj
        }
    },
    /**
     * creates a new object containing the values of the signature object plus the public key, encoded as a base64 string
     * @param  {Object}   signatureObject the signature object containing v,r,s
     * @param  {Buffer}   publicKey       the ethereum public key for later signature verification
     * @param  {String}   bufferEncoding  (optional) the encoding to be used for remaining buffers 
     * @param  {Function} cb              (optional) callback function
     * @return {String}                   Base64-encoded String representation of the input
     */
    signatureToBase64String: function(signatureObject, publicKey, bufferEncoding = DEFAULT_ENCODING, cb = null){
        var clonedSignatureObj = {
            v: signatureObject.v,
            r: signatureObject.r,
            s: signatureObject.s,
            publicKey: publicKey
        }
        bufferEncoding = getEncodingOrDefault(bufferEncoding)
        if(isFunction(cb)){
            module.exports.convertBuffersToStrings(clonedSignatureObj, bufferEncoding, function(convertedObj){
                var base64String = Buffer.from(JSON.stringify(convertedObj)).toString('base64')
                return cb(null, base64String)
            })
        } else {
            var convertedObj = module.exports.convertBuffersToStrings(clonedSignatureObj, bufferEncoding)
            var base64String = Buffer.from(JSON.stringify(convertedObj)).toString('base64')
            return base64String
        }
    },
    /**
     * recover signature object from base64-encoded string
     * @param  {String}   base64String   String to decode
     * @param  {String}   bufferEncoding encoding for recovering the buffers inside the object
     * @param  {Function} cb             callback function
     * @return {Object}                  Signature object recovered from the input string, or Error object if an error occured
     */
    signatureFromBase64String: function(base64String, bufferEncoding = DEFAULT_ENCODING, cb = null){
        bufferEncoding = getEncodingOrDefault(bufferEncoding)
        var decodedObj = JSON.parse(Buffer.from(base64String, 'base64').toString())
        var result = {}
        if('v' in decodedObj && 'r' in decodedObj && 's' in decodedObj){
            result = decodedObj
            result.s = Buffer.from(result.s, bufferEncoding)
            result.r = Buffer.from(result.r, bufferEncoding)
            if('publicKey' in decodedObj){
                result.publicKey = Buffer.from(result.publicKey, bufferEncoding)
            }
        }
        else {
            result = new Error("decoded object does not contain all required elements!")
        }
        if(isFunction(cb)){
            if(result instanceof Error){
                return cb(result)
            } else {
                return cb(null, result)
            }
        } else {
            return result
        }
    }
}