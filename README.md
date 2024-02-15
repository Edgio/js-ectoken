# js-ectoken
> _JavaScript implementation of Edgio token (`ectoken`)_

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

JavaScript implementation of the "Edgio Token" (`ectoken`) - see main repo [ectoken](https://github.com/edgio/ectoken) for more details.

## Install

1. Clone this repo.
2. `cd` into the repo directory
3. Run `npm install`

## Usage

This library is provided in CommonJS (CJS) format. To include the library in a script, `require` it:
```js
const { ECToken, encrypt, decrypt } = require('./ECToken.js')

const ec_token = new ECToken()
ec_token.addValue('ec_country_allow', 'US')
// Add additional directives in the same way.

const token = encrypt('my-secret-key', ec_token)
const plaintext = decrypt('my-secret-key', token)
```

## Contribute

We welcome issues, questions, and pull requests.

## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `License-2.0.txt` file for the full terms.