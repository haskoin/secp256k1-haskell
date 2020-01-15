# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

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
