const { ECToken, encrypt, decrypt } = require('./ECToken.js');

(async () => {
  // Create the token.
  const ec_token = new ECToken()
  ec_token.addValue('ec_country_allow', 'US')
  ec_token.addValue('ec_country_allow', 'CA')
  ec_token.addValue('ec_expire', (Date.now() / 1000) + (60 * 60 * 24))
  
  // Encrypt and encode it.
  const ec_token_str = await encrypt('my-secret-key', ec_token)
  console.log(`Encoded: ${ec_token_str}`)

  console.log(' ')
  
  // Now decrypt it back to plaintext.
  const plaintext = await decrypt('my-secret-key', ec_token_str)
  console.log(`Plaintext: ${plaintext}`)

  process.exit()
})()
