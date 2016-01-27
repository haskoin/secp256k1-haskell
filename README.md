# Haskell bindings for secp256k1

This project contains Haskell bindings for the secp256k1 library from the Bitcoin Core project.

## Installing

Although it is more common that you’ll want to just use this library as part of a project, here are the stand-alone installation instructions:

```sh
git clone --recursive https://github.com/xenog/secp256k1.git
cd secp256k1
stack install
```

This library contains a submodule that points to the latest supported version of the [upstream code](https://github.com/bitcoin/secp256k1).
