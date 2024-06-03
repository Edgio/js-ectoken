# @edgio/ectoken
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

```
$ npm install @edgio/js-ectoken
```

## Usage

```js
const { ECToken, encrypt, decrypt } = require('@edgio/js-ectoken')

const ec_token = new ECToken()
ec_token.addValue('ec_country_allow', 'US')
// Add additional directives in the same way.

const token = await encrypt('my-secret-key', ec_token)
const plaintext = await decrypt('my-secret-key', token)
```

If installing this library as a replacement for [`ectoken-nodejs`](https://github.com/hattan/ectoken-nodejs), import the `V3` namespace instead:

```js
const { V3 } = require('@edgio/js-ectoken')

const token = await V3.encrypt('my-secret-key', 'some_param=valueA&some_other_param=valueB')
const plaintext = await V3.decrypt('my-secret-key', token)
```

**Please Note**: because this version of the token generator uses `crypto.subtle`, the `encrypt` and `decrypt` functions **are now asynchronous.**

The `ECToken` helper class is optional for both the namespaced and non-namespaced import variations. The `encrypt` function will accept either an `ECToken` object or a plain `string`.

## Contribute

We welcome issues, questions, and pull requests.

## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `License-2.0.txt` file for the full terms.