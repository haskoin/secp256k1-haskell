# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 0.6.1
### Changed
- Bump version and LTS Haskell.
- Update dependencies.

## 0.6.0
### Changed
- Remove all use of CPP.
- Depend on base16 instead of the old base16-bytestring package.
- Target ghc-9.0.1 compiler.

### Fixed
- Do not crash on bytestrings that are backed by null C pointers.

## 0.5.0
### Changed
- Include version boundaries and other changes submitted by Emily Pillmore.

## 0.4.0
### Changed
- Remove fragile ForeignPtr implementation in favor of just storing ByteStrings.
- Reuse memory instead of copying when possible.

## 0.3.1
### Fixed
- Use unsafe calls in FFI.

## 0.3.0
### Fixed
- Compiles with all flags now.

### Added
- Script to compile with all flags.

### Removed
- Remove ECDH support.
- Remove Schnorr support.
- Remove Recovery support.

## 0.2.5
### Changed
- Reuse context aggressively.
- Generate context in a single thread.

### Fixed
- Memory deallocation bug.

## 0.2.4
### Changed
- Update Cabal and package version.

## 0.2.3
### Changed
- Return meaningful error upon encountering weird ret status from upstream code.

### Added
- Test parallel signature creation and verification.

## 0.2.2
### Removed
- Hide tweak negation behind a flag for compatibilidy with Debian 9.

### Fixed
- Correct code that was not compiling with some flags enabled.

## 0.2.1
### Changed
- Do not depend on hardcoded DER signatures in tests.

## 0.2.0
### Added
- Support for ECDH APIs.
- Support for Schnorr APIs.

### Removed
- Enabling key recovery APIs need a flag.

## 0.1.8
### Added
- Add missing `NFData` instances for some types.

## 0.1.7
### Added
- Add `NFData` instances for all types.

## 0.1.6
### Added
- Use `pkgconfig` for C library dependency.

## 0.1.5
### Added
- Flag for ECDH bindings.

## 0.1.4
### Changed
- Constrain imports to avoid clashes with a QuickCheck function.

## 0.1.3
### Added
- Hashable instances for various types.

## 0.1.2
### Changed
- Separate dependencies between library and tests.
- Remove `hspec` default to prevent problems with Nix.

### Removed
- Dependency to `cryptohash` not needed.

## 0.1.1
### Changed
- Update changelog to reflect name and version change.
- Update to LTS Haskell 12.9.

## 0.1.0
### Changed
- Name of package change from `secp256k1` to `secp256k1-haskell` to avoid Nix conflicts.
