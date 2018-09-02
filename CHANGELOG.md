# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## 1.1.2
### Changed
- Simplify `Show` and `Read` instances.

## 1.1.1
### Removed
- Old obvious installation instructions from `README.md` file.

### Changed
- Fix arbitrary instances such that unwanted colissions are less likely.

## 1.1.0
### Removed
- Lax parsing for DER.
- DER parsing of secret keys.
- Embedded code for library.

## 1.0.0 [YANKED]
### Added
- Changelog.

### Changed
- `Show`/`Read` instances now isomorphic to Haskell code.
- Semantic versioning.
- `Hspec` tests.
