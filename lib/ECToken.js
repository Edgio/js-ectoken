/**
 * A class to manage Edgecast Token creation.
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
   * @deprecated since v2.0.0; use toString() instead.
   */
  serialize() {
    return this.toString()
  }

  /**
   * Serialize the token object as a valid EdgeCast Token.
   * @returns {String}
   */
  toString() {
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

// Export the ECToken helper class.
module.exports = {
  ECToken
}
