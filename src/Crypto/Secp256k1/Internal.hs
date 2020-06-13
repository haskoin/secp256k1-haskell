{-# LANGUAGE CPP             #-}
{-# LANGUAGE DeriveAnyClass  #-}
{-# LANGUAGE DeriveGeneric   #-}
{-# LANGUAGE RecordWildCards #-}
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

import           Control.DeepSeq       (NFData)
import           Control.Monad         (guard, unless)
import           Data.ByteString       (ByteString)
import qualified Data.ByteString       as BS
import           Data.ByteString.Short (ShortByteString, fromShort, toShort)
import           Data.Serialize        (Serialize (..))
import qualified Data.Serialize.Get    as Get
import qualified Data.Serialize.Put    as Put
import           Data.Void             (Void)
import           Foreign               (FunPtr, Ptr, Storable (..), alloca,
                                        castPtr, copyArray)
import           Foreign.C             (CInt (..), CSize (..), CString, CUChar,
                                        CUInt (..))
import           GHC.Generics          (Generic)
import           System.Entropy        (getEntropy)
import           System.IO.Unsafe      (unsafePerformIO)

data Ctx = Ctx

newtype PubKey64 = PubKey64 { getPubKey64 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Msg32 = Msg32 { getMsg32 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Sig64 = Sig64 { getSig64 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

data CompactSig =
    CompactSig
        { getCompactSigR :: !ShortByteString
        , getCompactSigS :: !ShortByteString
        }
    deriving (Show, Eq, Ord, Generic, NFData)

newtype RecSig65 = RecSig65 { getRecSig65 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Seed32 = Seed32 { getSeed32 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype SecKey32 = SecKey32 { getSecKey32 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Tweak32 = Tweak32 { getTweak32 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Nonce32 = Nonce32 { getNonce32 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Algo16 = Algo16 { getAlgo16 :: ShortByteString }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype CtxFlags = CtxFlags { getCtxFlags :: CUInt }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype SerFlags = SerFlags { getSerFlags :: CUInt }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

newtype Ret = Ret { getRet :: CInt }
    deriving (Read, Show, Eq, Ord, Generic, NFData)

verify :: CtxFlags
verify = CtxFlags 0x0101

sign :: CtxFlags
sign = CtxFlags 0x0201

signVerify :: CtxFlags
signVerify = CtxFlags 0x0301

compressed :: SerFlags
compressed = SerFlags 0x0102

uncompressed :: SerFlags
uncompressed = SerFlags 0x0002

useByteString :: ByteString -> ((Ptr CUChar, CSize) -> IO a) -> IO a
useByteString bs f =
    BS.useAsCStringLen bs $ \(b, l) -> f (castPtr b, fromIntegral l)

packByteString :: (Ptr CUChar, CSize) -> IO ByteString
packByteString (b, l) = BS.packCStringLen (castPtr b, fromIntegral l)

instance Storable PubKey64 where
    sizeOf _ = 64
    alignment _ = 1
    peek p = PubKey64 . toShort <$> packByteString (castPtr p, 64)
    poke p (PubKey64 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 64

instance Storable Sig64 where
    sizeOf _ = 64
    alignment _ = 1
    peek p = Sig64 . toShort <$> packByteString (castPtr p, 64)
    poke p (Sig64 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 64

instance Storable CompactSig where
    sizeOf _ = 64
    alignment _ = 1
    peek p = do
        bs <- BS.packCStringLen (castPtr p, 64)
        let (r, s) = BS.splitAt 32 bs
        guard $ BS.length r == 32
        guard $ BS.length s == 32
        return CompactSig { getCompactSigR = toShort r
                          , getCompactSigS = toShort s
                          }
    poke p CompactSig{..} =
        useByteString bs $ \(b, _) -> copyArray (castPtr p) b 64
      where
        bs = fromShort getCompactSigR `BS.append` fromShort getCompactSigS

instance Serialize CompactSig where
    get = do
        r <- Get.getByteString 32
        s <- Get.getByteString 32
        return CompactSig { getCompactSigR = toShort r
                          , getCompactSigS = toShort s
                          }
    put (CompactSig r s) = do
        Put.putShortByteString r
        Put.putShortByteString s

instance Storable Msg32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = Msg32 . toShort <$> packByteString (castPtr p, 32)
    poke p (Msg32 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 32

instance Storable Seed32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = Seed32 . toShort <$> packByteString (castPtr p, 32)
    poke p (Seed32 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 32

instance Storable SecKey32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = SecKey32 . toShort <$> packByteString (castPtr p, 32)
    poke p (SecKey32 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 32

instance Storable Tweak32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = Tweak32 . toShort <$> packByteString (castPtr p, 32)
    poke p (Tweak32 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 32

instance Storable Nonce32 where
    sizeOf _ = 32
    alignment _ = 1
    peek p = Nonce32 . toShort <$> packByteString (castPtr p, 32)
    poke p (Nonce32 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 32

instance Storable Algo16 where
    sizeOf _ = 16
    alignment _ = 1
    peek p = Algo16 . toShort <$> packByteString (castPtr p, 16)
    poke p (Algo16 k) = useByteString (fromShort k) $
        \(b, _) -> copyArray (castPtr p) b 16

isSuccess :: Ret -> Bool
isSuccess (Ret 0) = False
isSuccess (Ret 1) = True
isSuccess (Ret n) = error $ "isSuccess expected 0 or 1 but got " <> show n

{-# NOINLINE ctx #-}
ctx :: Ptr Ctx
ctx = unsafePerformIO $ do
    x <- contextCreate signVerify
    e <- getEntropy 32
    ret <- alloca $ \s -> do
        poke s (Seed32 (toShort e))
        contextRandomize x s
    unless (isSuccess ret) $ error "failed to randomize context"
    return x

foreign import ccall
    "secp256k1.h secp256k1_context_create"
    contextCreate
    :: CtxFlags
    -> IO (Ptr Ctx)

foreign import ccall
    "secp256k1.h secp256k1_context_clone"
    contextClone
    :: Ptr Ctx
    -> IO (Ptr Ctx)

foreign import ccall
    "secp256k1.h &secp256k1_context_destroy"
    contextDestroy
    :: FunPtr (Ptr Ctx -> IO ())

foreign import ccall
    "secp256k1.h secp256k1_context_set_illegal_callback"
    setIllegalCallback
    :: Ptr Ctx
    -> FunPtr (CString -> Ptr a -> IO ()) -- ^ message, data
    -> Ptr a                              -- ^ data
    -> IO ()

foreign import ccall
    "secp256k1.h secp256k1_context_set_error_callback"
    setErrorCallback
    :: Ptr Ctx
    -> FunPtr (CString -> Ptr a -> IO ()) -- ^ message, data
    -> Ptr a                              -- ^ data
    -> IO ()

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_parse"
    ecPubKeyParse
    :: Ptr Ctx
    -> Ptr PubKey64
    -> Ptr CUChar -- ^ encoded public key array
    -> CSize      -- ^ size of encoded public key array
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_serialize"
    ecPubKeySerialize
    :: Ptr Ctx
    -> Ptr CUChar -- ^ array for encoded public key, must be large enough
    -> Ptr CSize  -- ^ size of encoded public key, will be updated
    -> Ptr PubKey64
    -> SerFlags
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_signature_parse_compact"
    ecdsaSignatureParseCompact
    :: Ptr Ctx
    -> Ptr Sig64
    -> Ptr CompactSig
    -> IO Ret


foreign import ccall
    "secp256k1.h secp256k1_ecdsa_signature_parse_der"
    ecdsaSignatureParseDer
    :: Ptr Ctx
    -> Ptr Sig64
    -> Ptr CUChar -- ^ encoded DER signature
    -> CSize      -- ^ size of encoded signature
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_signature_serialize_der"
    ecdsaSignatureSerializeDer
    :: Ptr Ctx
    -> Ptr CUChar -- ^ array for encoded signature, must be large enough
    -> Ptr CSize  -- ^ size of encoded signature, will be updated
    -> Ptr Sig64
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_signature_serialize_compact"
    ecdsaSignatureSerializeCompact
    :: Ptr Ctx
    -> Ptr CompactSig
    -> Ptr Sig64
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_verify"
    ecdsaVerify
    :: Ptr Ctx
    -> Ptr Sig64
    -> Ptr Msg32
    -> Ptr PubKey64
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_signature_normalize"
    ecdsaSignatureNormalize
    :: Ptr Ctx
    -> Ptr Sig64 -- ^ output
    -> Ptr Sig64 -- ^ input
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ecdsa_sign"
    ecdsaSign
    :: Ptr Ctx
    -> Ptr Sig64
    -> Ptr Msg32
    -> Ptr SecKey32
    -> Ptr Void
    -> Ptr a -- ^ nonce data
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_seckey_verify"
    ecSecKeyVerify
    :: Ptr Ctx
    -> Ptr SecKey32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_create"
    ecPubKeyCreate
    :: Ptr Ctx
    -> Ptr PubKey64
    -> Ptr SecKey32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_privkey_tweak_add"
    ecSecKeyTweakAdd
    :: Ptr Ctx
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_privkey_negate"
    ecTweakNegate
    :: Ptr Ctx
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_tweak_add"
    ecPubKeyTweakAdd
    :: Ptr Ctx
    -> Ptr PubKey64
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_privkey_tweak_mul"
    ecSecKeyTweakMul
    :: Ptr Ctx
    -> Ptr SecKey32
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_tweak_mul"
    ecPubKeyTweakMul
    :: Ptr Ctx
    -> Ptr PubKey64
    -> Ptr Tweak32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_context_randomize"
    contextRandomize
    :: Ptr Ctx
    -> Ptr Seed32
    -> IO Ret

foreign import ccall
    "secp256k1.h secp256k1_ec_pubkey_combine"
    ecPubKeyCombine
    :: Ptr Ctx
    -> Ptr PubKey64 -- ^ pointer to public key storage
    -> Ptr (Ptr PubKey64) -- ^ pointer to array of public keys
    -> CInt -- ^ number of public keys
    -> IO Ret
