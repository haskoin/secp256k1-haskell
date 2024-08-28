-- |
-- Module      : Crypto.Secp256k1.Internal.BaseOps
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Internal.BaseOps where

import Crypto.Secp256k1.Internal.ForeignTypes
  ( Compact64,
    KeyPair,
    LCtx,
    Msg32,
    NonceFun,
    PubKey64,
    Ret,
    SecKey32,
    Seed32,
    SerFlags,
    Sig64,
    Tweak32,
    XOPubKey32,
  )
import Foreign (FunPtr, Ptr)
import Foreign.C
  ( CInt (..),
    CSize (..),
    CUChar,
    CUInt (..),
  )

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_parse"
  ecPubKeyParse ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    -- | encoded public key array
    Ptr CUChar ->
    -- | size of encoded public key array
    CSize ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_serialize"
  ecPubKeySerialize ::
    Ptr LCtx ->
    -- | array for encoded public key, must be large enough
    Ptr CUChar ->
    -- | size of encoded public key, will be updated
    Ptr CSize ->
    Ptr PubKey64 ->
    SerFlags ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
  ecdsaSignatureParseCompact ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr Compact64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_der"
  ecdsaSignatureParseDer ::
    Ptr LCtx ->
    Ptr Sig64 ->
    -- | encoded DER signature
    Ptr CUChar ->
    -- | size of encoded signature
    CSize ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
  ecdsaSignatureSerializeDer ::
    Ptr LCtx ->
    -- | array for encoded signature, must be large enough
    Ptr CUChar ->
    -- | size of encoded signature, will be updated
    Ptr CSize ->
    Ptr Sig64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
  ecdsaSignatureSerializeCompact ::
    Ptr LCtx ->
    Ptr Compact64 ->
    Ptr Sig64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_verify"
  ecdsaVerify ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr Msg32 ->
    Ptr PubKey64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_normalize"
  ecdsaSignatureNormalize ::
    Ptr LCtx ->
    -- | output
    Ptr Sig64 ->
    -- | input
    Ptr Sig64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_sign"
  ecdsaSign ::
    Ptr LCtx ->
    Ptr Sig64 ->
    Ptr Msg32 ->
    Ptr SecKey32 ->
    FunPtr (NonceFun a) ->
    -- | nonce data
    Ptr a ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_verify"
  ecSecKeyVerify ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_create"
  ecPubKeyCreate ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr SecKey32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_tweak_add"
  ecSecKeyTweakAdd ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_negate"
  ecTweakNegate ::
    Ptr LCtx ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_tweak_add"
  ecPubKeyTweakAdd ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_tweak_mul"
  ecSecKeyTweakMul ::
    Ptr LCtx ->
    Ptr SecKey32 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
  ecPubKeyTweakMul ::
    Ptr LCtx ->
    Ptr PubKey64 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_combine"
  ecPubKeyCombine ::
    Ptr LCtx ->
    -- | pointer to public key storage
    Ptr PubKey64 ->
    -- | pointer to array of public keys
    Ptr (Ptr PubKey64) ->
    -- | number of public keys
    CInt ->
    IO Ret

foreign import ccall unsafe "secp256k1.h secp256k1_schnorrsig_sign"
  schnorrSign ::
    Ptr LCtx ->
    -- | Signature
    Ptr Sig64 ->
    -- | Message
    Ptr Msg32 ->
    -- | Keypair
    Ptr KeyPair ->
    -- | Randomness
    Ptr CUChar ->
    IO CInt

foreign import ccall unsafe "secp256k1.h secp256k1_schnorrsig_verify"
  schnorrVerify ::
    Ptr LCtx ->
    -- | Signature
    Ptr Sig64 ->
    -- | Message
    Ptr Msg32 ->
    -- | Message length
    CSize ->
    -- | X-Only pubkey
    Ptr XOPubKey32 ->
    IO CInt

foreign import ccall unsafe "secp256k1.h secp256k1_keypair_create"
  keyPairCreate ::
    Ptr LCtx ->
    -- | Keypair
    Ptr KeyPair ->
    -- | Secret key
    Ptr SecKey32 ->
    IO CInt

foreign import ccall unsafe "secp256k1.h secp256k1_xonly_pubkey_parse"
  xOnlyPubKeyParse ::
    Ptr LCtx ->
    -- | Parsed X-Only pubkey
    Ptr XOPubKey32 ->
    -- | Input buffer
    Ptr CUChar ->
    IO CInt

foreign import ccall unsafe "secp256k1.h secp256k1_xonly_pubkey_serialize"
  xOnlyPubKeySerialize ::
    Ptr LCtx ->
    -- | Output buffer
    Ptr CUChar ->
    -- | X-Only pubkey
    Ptr XOPubKey32 ->
    IO CInt

foreign import ccall unsafe "secp256k1.h secp256k1_xonly_pubkey_from_pubkey"
  xOnlyPubKeyFromPubKey ::
    Ptr LCtx ->
    -- | X-only pubkey
    Ptr XOPubKey32 ->
    -- | Parity
    Ptr CInt ->
    -- | Pubkey
    Ptr PubKey64 ->
    IO CInt
