const crypto = require('crypto')
const base64url = require('base64url')

const iv_size_bytes = 12
const aes_gcm_tag_size_bytes = 16

/**
 * An EdgeCast Token
 */
class ECToken {
  constructor() {
    // Set default values for all valid token fields.
    this.values = {
      ec_expire: 0,
      ec_country_allow: [],
      ec_country_deny: [],
      ec_url_allow: [],
      ec_host_allow: [],
      ec_host_deny: [],
      ec_ref_allow: [],
      ec_ref_deny: [],
      ec_clientip: [],
      ec_proto_allow: [],
      ec_proto_deny: []
    }
  }

  /**
   * Set or append a value to the token.
   * @param {String} key The key to set or append.
   * @param {String} value The value to add.
   * @returns None
   */
  addValue(key, value) {
    if (!(key in this.values)) {
      throw new Error(`Invalid key: ${key}`)
    }

    if (key === 'ec_expire') {
      this.values.ec_expire = parseInt(value)
      return
    }

    // All other keys can be multivalue.
    if (!this.values[key].includes(value)) {
      this.values[key].push(value)
    }
  }

  /**
   * Serialize the token object as a valid EdgeCast Token.
   * @returns {String} The serialized output containing all the options the user set.
   */
  serialize() {
    let token = Object.keys(this.values).reduce((acc, curr) => {
      if (curr === 'ec_expire' && this.values.ec_expire && this.values.ec_expire > 0) {
        acc.push(`ex_expire=${this.values.ec_expire}`)
      } else {
        if (this.values[curr].length) {
          acc.push(`${curr}=${this.values[curr].join(',')}`)
        }
      }
      return acc
    }, []).join('&')
    return token
  }
}

/**
 * Encrypt an ECToken with a key.
 * @param {String} key The secret key to encode the token.
 * @param {ECToken} token The token to encrypt.
 * @param {Boolean} verbose Whether to print verbose output.
 * @returns {String} The encrypted token.
 */
function encrypt(key, token, verbose = false) {
  const token_str = token.serialize().toString('utf-8')
  const key_encoded = key.toString('utf-8')

  const key_digest = crypto.createHash('sha256').update(key_encoded).digest()

  const iv = crypto.randomBytes(iv_size_bytes)

  const encryptor = crypto.createCipheriv('aes-256-gcm', key_digest, iv).setAutoPadding(false)
  const ciphertext = encryptor.update(token_str)
  encryptor.final('utf-8')
  const tag = encryptor.getAuthTag()
  const iv_ciphertext = Buffer.concat([iv, ciphertext, tag])

  if (verbose) {
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| iv:', iv.toString('hex'))
    console.log('| ciphertext:', ciphertext.toString('hex'))
    console.log('| tag:', tag.toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| encoded_token:', iv_ciphertext.toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
  }

  return base64url.encode(iv_ciphertext)
}

/**
 * 
 * @param {String} key The secret to decode the token.
 * @param {String} token The token to decrypt.
 * @param {Boolean} verbose Whether to print verbose output.
 * @returns {String} The decrypted token.
 */
function decrypt(key, token, verbose = false) {
  const key_digest = crypto.createHash('sha256').update(key).digest()

  const decoded_token = base64url.toBuffer(token)

  // First n bytes (iv_size_bytes) is the iv.
  const iv = decoded_token.subarray(0, iv_size_bytes)

  // Last n bytes (aes_gcm_tag_size_bytes) is the tag.
  const tag = decoded_token.subarray(-aes_gcm_tag_size_bytes)

  // Middle bit is the ciphertext.
  const ciphertext = decoded_token.subarray(iv_size_bytes, -aes_gcm_tag_size_bytes)

  if (verbose) {
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| decoded_token:', decoded_token.toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| iv:', iv.toString('hex'))
    console.log('| ciphertext:', ciphertext.toString('hex'))
    console.log('| tag:', tag.toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key_digest, iv).setAutoPadding(false)
  decipher.setAuthTag(tag)
  const decrypted_buffer = decipher.update(ciphertext)
  decipher.final('utf8')
  const decrypted_str = decrypted_buffer.toString('utf-8')

  if (verbose) {
    console.log('| decrypted_str:', decrypted_str)
    console.log('+---------------------------------------------------------------------------------------------------')
  }

  return decrypted_str
}

module.exports = {
  ECToken,
  encrypt,
  decrypt
}