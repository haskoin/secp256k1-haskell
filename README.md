# Haskell bindings for secp256k1

This project contains Haskell bindings for the [secp256k1](https://github.com/bitcoin/secp256k1) library from the Bitcoin Core project.

## Installing

Although it is more common that you’ll want to just use this library as part of a project, here are the stand-alone installation instructions:

```sh
git clone --recursive https://github.com/haskoin/secp256k1-haskell.git
cd secp256k1
stack install
```

This library contains a submodule that points to the latest supported version of [secp256k1](https://github.com/bitcoin/secp256k1).

It is not necessary to install the secp256k1 library in your system beforehand. This package will automatically compile and link the C code from upstream. It will not attempt to link against the secp256k1 library in your system if you already have it.
