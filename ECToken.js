const crypto = require('crypto')
const base64url = require('base64url')

const iv_size_bytes = 12

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
        acc.push(`ec_expire=${this.values.ec_expire}`)
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
 * @returns {Promise<String>} The encrypted token.
 */
async function encrypt(key, token, verbose = false) {
  const token_str = new TextEncoder().encode(token.serialize())
  const key_encoded = new TextEncoder().encode(key)

  const key_digest = await crypto.subtle.digest('SHA-256', key_encoded)

  const iv = crypto.getRandomValues(new Uint8Array(iv_size_bytes))

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key_digest,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  )

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    token_str
  )

  const iv_ciphertext = new Uint8Array(iv.byteLength + ciphertext.byteLength)
  iv_ciphertext.set(new Uint8Array(iv), 0)
  iv_ciphertext.set(new Uint8Array(ciphertext), iv.byteLength)

  if (verbose) {
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| iv:', Buffer.from(iv).toString('hex'))
    console.log('| ciphertext:', Buffer.from(ciphertext).toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| encoded_token:', Buffer.from(iv_ciphertext).toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
  }

  return base64url.encode(iv_ciphertext)
}

/**
 * 
 * @param {String} key The secret to decode the token.
 * @param {String} token The token to decrypt.
 * @param {Boolean} verbose Whether to print verbose output.
 * @returns {Promise<String>} The decrypted token.
 */
async function decrypt(key, token, verbose = false) {
  const key_encoded = new TextEncoder().encode(key)
  const key_digest = await crypto.subtle.digest('SHA-256', key_encoded)

  const decoded_token = base64url.toBuffer(token)

  // First n bytes (iv_size_bytes) is the iv.
  const iv = decoded_token.subarray(0, iv_size_bytes)

  // last bit is the ciphertext.
  const ciphertext = decoded_token.subarray(iv_size_bytes)

  if (verbose) {
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| decoded_token:', decoded_token.toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
    console.log('| iv:', iv.toString('hex'))
    console.log('| ciphertext:', ciphertext.toString('hex'))
    console.log('+---------------------------------------------------------------------------------------------------')
  }

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key_digest,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  )

  const decrypted_str = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  )

  if (verbose) {
    console.log('| decrypted_str:', new TextDecoder().decode(decrypted_str))
    console.log('+---------------------------------------------------------------------------------------------------')
  }

  return new TextDecoder().decode(decrypted_str)
}

module.exports = {
  ECToken,
  encrypt,
  decrypt
}
