'use strict';

const chai = require('chai')
const expect = chai.expect
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const { ECToken, encrypt, decrypt } = require('../index.js')

describe('ECToken Helper Class', function() {
  it('should add a single value correctly', function() {
    const token = new ECToken
    token.addValue('ec_country_allow', 'CA')
    expect(token.values.ec_country_allow).to.deep.equal(['CA'])
  })

  it('should add multiple values correctly', function() {
    const token = new ECToken
    token.addValue('ec_country_allow', 'US')
    token.addValue('ec_country_allow', 'CA')
    expect(token.values.ec_country_allow).to.deep.equal(['US', 'CA'])
  })

  it('should deduplicate multi-value entries', function() {
    const token = new ECToken
    token.addValue('ec_country_allow', 'US')
    token.addValue('ec_country_allow', 'US')
    expect(token.values.ec_country_allow).to.deep.equal(['US'])
  })

  it('should serialize to a string properly', function() {
    const token = new ECToken
    token.addValue('ec_country_allow', 'US')
    token.addValue('ec_country_allow', 'CA')
    token.addValue('ec_country_deny', 'MX')
    const serialized = token.toString()
    expect(serialized).to.equal('ec_country_allow=US,CA&ec_country_deny=MX')
  })

  it('should not allow arbitrary parameters', function() {
    expect(function() {
      const token = new ECToken
      token.addValue('arbitrary', 'value')
    }).to.throw()
  })
})

describe('Encryption and Decryption', function() {
  const key = 'my-secret-key'  // openssl rand -hex 8

  // Specify a hard-coded string.
  const params = 'ec_expire=12345678&ec_clientip=1.2.3.4'

  // Specify the same token as a helper object.
  const token = new ECToken
  token.addValue('ec_expire', 12345678)
  token.addValue('ec_clientip', '1.2.3.4')

  // Specify an encrypted token using the key above.
  const encrypted = 'WWNONztpLdGM11awAYiFRuIIiIG1LOBQaO2cEtCXjT5PelAA-Tavv7eD9YtSeGM13uQsobIkL0xYf6DZLzM6iMbe'

  it('should successfully encrypt a simple string', function() {
    return expect(Promise.resolve(
      encrypt(key, params)
    )).to.eventually.not.be.rejected
  })
  
  it('should succesfully encrypt a helper token', function() {
    expect(function() {
      return expect(Promise.resolve(
        encrypt(key, token)
      )).to.eventually.be.a('string')
    })
  })

  it('should return a string when encrypting', function() {
    return expect(Promise.resolve(encrypt(key, params))).to.eventually.be.a('string')
  })

  it('should decrypt a known token', function() {
    return expect(Promise.resolve(
      decrypt(key, encrypted)
    )).to.eventually.equal(params)
  })
})
