-- |
-- Module      : Crypto.Secp256k1.Internal
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
{-# LANGUAGE ImportQualifiedPost #-}
module Crypto.Secp256k1.Internal where

import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Unsafe qualified as BU
import Foreign (FunPtr, Ptr, castPtr)
import Foreign.C
  ( CInt (..),
    CSize (..),
    CString,
    CUChar,
    CUInt (..),
  )
import GHC.Generics (Selector (selDecidedStrictness))
import System.Entropy (getEntropy)

data LCtx

data PubKey64

data Msg32

data Sig64

data Seed32

data Compact64

data SecKey32

data Tweak32

type CtxFlags = CUInt

type SerFlags = CUInt

type Ret = CInt

type NonceFun a =
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr CUChar ->
  Ptr a ->
  CInt ->
  IO CInt

type Ctx = Ptr LCtx

verify :: CtxFlags
verify = 0x0101

sign :: CtxFlags
sign = 0x0201

signVerify :: CtxFlags
signVerify = 0x0301

compressed :: SerFlags
compressed = 0x0102

uncompressed :: SerFlags
uncompressed = 0x0002

isSuccess :: Ret -> Bool
isSuccess 0 = False
isSuccess 1 = True
isSuccess n = error $ "isSuccess expected 0 or 1 but got " ++ show n

unsafeUseByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
unsafeUseByteString bs f =
  BU.unsafeUseAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

useByteString :: ByteString -> ((Ptr a, CSize) -> IO b) -> IO b
useByteString bs f =
  BS.useAsCStringLen bs $ \(b, l) ->
    f (castPtr b, fromIntegral l)

unsafePackByteString :: (Ptr a, CSize) -> IO ByteString
unsafePackByteString (b, l) =
  BU.unsafePackMallocCStringLen (castPtr b, fromIntegral l)

packByteString :: (Ptr a, CSize) -> IO ByteString
packByteString (b, l) =
  BS.packCStringLen (castPtr b, fromIntegral l)

withRandomSeed :: (Ptr Seed32 -> IO a) -> IO a
withRandomSeed go = do
  bs <- getEntropy 32
  useByteString bs $ go . fst

foreign import ccall safe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    CtxFlags ->
    IO Ctx

foreign import ccall safe "secp256k1.h secp256k1_context_clone"
  contextClone ::
    Ctx ->
    IO Ctx

foreign import ccall safe "secp256k1.h secp256k1_context_destroy"
  contextDestroy ::
    Ctx ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_set_illegal_callback"
  setIllegalCallback ::
    Ctx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_set_error_callback"
  setErrorCallback ::
    Ctx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_parse"
  ecPubKeyParse ::
    Ctx ->
    Ptr PubKey64 ->
    -- | encoded public key array
    Ptr CUChar ->
    -- | size of encoded public key array
    CSize ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_serialize"
  ecPubKeySerialize ::
    Ctx ->
    -- | array for encoded public key, must be large enough
    Ptr CUChar ->
    -- | size of encoded public key, will be updated
    Ptr CSize ->
    Ptr PubKey64 ->
    SerFlags ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
  ecdsaSignatureParseCompact ::
    Ctx ->
    Ptr Sig64 ->
    Ptr Compact64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_parse_der"
  ecdsaSignatureParseDer ::
    Ctx ->
    Ptr Sig64 ->
    -- | encoded DER signature
    Ptr CUChar ->
    -- | size of encoded signature
    CSize ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
  ecdsaSignatureSerializeDer ::
    Ctx ->
    -- | array for encoded signature, must be large enough
    Ptr CUChar ->
    -- | size of encoded signature, will be updated
    Ptr CSize ->
    Ptr Sig64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
  ecdsaSignatureSerializeCompact ::
    Ctx ->
    Ptr Compact64 ->
    Ptr Sig64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_verify"
  ecdsaVerify ::
    Ctx ->
    Ptr Sig64 ->
    Ptr Msg32 ->
    Ptr PubKey64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_signature_normalize"
  ecdsaSignatureNormalize ::
    Ctx ->
    -- | output
    Ptr Sig64 ->
    -- | input
    Ptr Sig64 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ecdsa_sign"
  ecdsaSign ::
    Ctx ->
    Ptr Sig64 ->
    Ptr Msg32 ->
    Ptr SecKey32 ->
    FunPtr (NonceFun a) ->
    -- | nonce data
    Ptr a ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_seckey_verify"
  ecSecKeyVerify ::
    Ctx ->
    Ptr SecKey32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_create"
  ecPubKeyCreate ::
    Ctx ->
    Ptr PubKey64 ->
    Ptr SecKey32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_tweak_add"
  ecSecKeyTweakAdd ::
    Ctx ->
    Ptr SecKey32 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_negate"
  ecTweakNegate ::
    Ctx ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall unsafe "secp256k1.h secp256k1_ec_pubkey_tweak_add"
  ecPubKeyTweakAdd ::
    Ctx ->
    Ptr PubKey64 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_privkey_tweak_mul"
  ecSecKeyTweakMul ::
    Ctx ->
    Ptr SecKey32 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
  ecPubKeyTweakMul ::
    Ctx ->
    Ptr PubKey64 ->
    Ptr Tweak32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_context_randomize"
  contextRandomize ::
    Ctx ->
    Ptr Seed32 ->
    IO Ret

foreign import ccall safe "secp256k1.h secp256k1_ec_pubkey_combine"
  ecPubKeyCombine ::
    Ctx ->
    -- | pointer to public key storage
    Ptr PubKey64 ->
    -- | pointer to array of public keys
    Ptr (Ptr PubKey64) ->
    -- | number of public keys
    CInt ->
    IO Ret
