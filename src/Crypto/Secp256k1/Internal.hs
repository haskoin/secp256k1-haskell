{-|
Module      : Crypto.Secp256k1.Internal
License     : UNLICENSE
Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
Stability   : experimental
Portability : POSIX

The API for this module may change at any time. This is an internal module only
exposed for hacking and experimentation.
-}
module Crypto.Secp256k1.Internal where

import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Unsafe as BU
import           Foreign                (FunPtr, Ptr, castPtr)
import           Foreign.C              (CInt (..), CSize (..), CString, CUChar,
                                         CUInt (..))
import           System.IO.Unsafe       (unsafePerformIO)

data LCtx
data PubKey64
data Msg32
data Sig64
data Compact64
data Seed32
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

ctx :: Ctx
ctx = unsafePerformIO $ contextCreate signVerify
{-# NOINLINE ctx #-}

foreign import ccall safe
    "secp256k1.h secp256k1_context_create"
    contextCreate
    :: CtxFlags
    -> IO Ctx

foreign import ccall safe
    "secp256k1.h secp256k1_context_clone"
    contextClone
    :: Ctx
    -> IO Ctx

foreign import ccall safe
    "secp256k1.h &secp256k1_context_destroy"
    contextDestroy
    :: FunPtr (Ctx -> IO ())

foreign import ccall safe
    "secp256k1.h secp256k1_context_set_illegal_callback"
    setIllegalCallback
    :: Ctx
    -> FunPtr (CString -> Ptr a -> IO ()) -- ^ message, data
    -> Ptr a                              -- ^ data
    -> IO ()

foreign import ccall safe
    "secp256k1.h secp256k1_context_set_error_callback"
    setErrorCallback
    :: Ctx
    -> FunPtr (CString -> Ptr a -> IO ()) -- ^ message, data
    -> Ptr a                              -- ^ data
    -> IO ()

foreign import ccall safe
    "secp256k1.h secp256k1_ec_pubkey_parse"
    ecPubKeyParse
    :: Ctx
    -> Ptr PubKey64
    -> Ptr CUChar -- ^ encoded public key array
    -> CSize      -- ^ size of encoded public key array
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_pubkey_serialize"
    ecPubKeySerialize
    :: Ctx
    -> Ptr CUChar -- ^ array for encoded public key, must be large enough
    -> Ptr CSize  -- ^ size of encoded public key, will be updated
    -> Ptr PubKey64
    -> SerFlags
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
    ecdsaSignatureParseCompact
    :: Ctx
    -> Ptr Sig64
    -> Ptr Compact64
    -> IO Ret


foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_signature_parse_der"
    ecdsaSignatureParseDer
    :: Ctx
    -> Ptr Sig64
    -> Ptr CUChar -- ^ encoded DER signature
    -> CSize      -- ^ size of encoded signature
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
    ecdsaSignatureSerializeDer
    :: Ctx
    -> Ptr CUChar -- ^ array for encoded signature, must be large enough
    -> Ptr CSize  -- ^ size of encoded signature, will be updated
    -> Ptr Sig64
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
    ecdsaSignatureSerializeCompact
    :: Ctx
    -> Ptr Compact64
    -> Ptr Sig64
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_verify"
    ecdsaVerify
    :: Ctx
    -> Ptr Sig64
    -> Ptr Msg32
    -> Ptr PubKey64
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_signature_normalize"
    ecdsaSignatureNormalize
    :: Ctx
    -> Ptr Sig64 -- ^ output
    -> Ptr Sig64 -- ^ input
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ecdsa_sign"
    ecdsaSign
    :: Ctx
    -> Ptr Sig64
    -> Ptr Msg32
    -> Ptr SecKey32
    -> FunPtr (NonceFun a)
    -> Ptr a -- ^ nonce data
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_seckey_verify"
    ecSecKeyVerify
    :: Ctx
    -> Ptr SecKey32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_pubkey_create"
    ecPubKeyCreate
    :: Ctx
    -> Ptr PubKey64
    -> Ptr SecKey32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_privkey_tweak_add"
    ecSecKeyTweakAdd
    :: Ctx
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_privkey_negate"
    ecTweakNegate
    :: Ctx
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall unsafe
    "secp256k1.h secp256k1_ec_pubkey_tweak_add"
    ecPubKeyTweakAdd
    :: Ctx
    -> Ptr PubKey64
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_privkey_tweak_mul"
    ecSecKeyTweakMul
    :: Ctx
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
    ecPubKeyTweakMul
    :: Ctx
    -> Ptr PubKey64
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_context_randomize"
    contextRandomize
    :: Ctx
    -> Ptr Seed32
    -> IO Ret

foreign import ccall safe
    "secp256k1.h secp256k1_ec_pubkey_combine"
    ecPubKeyCombine
    :: Ctx
    -> Ptr PubKey64       -- ^ pointer to public key storage
    -> Ptr (Ptr PubKey64) -- ^ pointer to array of public keys
    -> CInt               -- ^ number of public keys
    -> IO Ret
