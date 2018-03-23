{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-|
Module      : Crypto.Secp256k1
License     : MIT
Maintainer  : Jean-Pierre Rupp <root@haskoin.com>
Stability   : experimental
Portability : POSIX

Crytpographic functions from Bitcoin’s secp256k1 library.
-}
module Crypto.Secp256k1
    ( -- * Messages
    Msg
    , msg
    , getMsg

    -- * Secret Keys
    , SecKey
    , secKey
    , getSecKey
    , derivePubKey
    , exportSecKey

    -- * Public Keys
    , PubKey
    , importPubKey
    , exportPubKey

    -- * Signatures
    , Sig
    , signMsg
    , verifySig
    , normalizeSig
    -- ** DER
    , importSig
    , laxImportSig
    , exportSig
    -- ** Compact
    , CompactSig(..)
    , exportCompactSig
    , importCompactSig
    -- * Recoverable
    , RecSig
    , CompactRecSig(..)
    , importCompactRecSig
    , exportCompactRecSig
    , convertRecSig
    , signRecMsg
    , recover

    -- * Addition & Multiplication
    , Tweak
    , tweak
    , getTweak
    , tweakAddSecKey
    , tweakMulSecKey
    , tweakAddPubKey
    , tweakMulPubKey
    , combinePubKeys
    ) where

import           Control.Monad
import           Crypto.Secp256k1.Internal
import           Data.Serialize
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import           Data.ByteString.Short     (fromShort, toShort)
import           Data.Maybe
import           Data.String
import           Data.String.Conversions
import           Foreign
import           System.IO.Unsafe
import           Test.QuickCheck
import           Text.Read

newtype PubKey = PubKey (ForeignPtr PubKey64)
newtype Msg = Msg (ForeignPtr Msg32)
newtype Sig = Sig (ForeignPtr Sig64)
newtype SecKey = SecKey (ForeignPtr SecKey32)
newtype Tweak = Tweak (ForeignPtr Tweak32)
newtype RecSig = RecSig (ForeignPtr RecSig65)

decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str = if BS.null r then Just bs else Nothing where
    (bs, r) = B16.decode $ cs str

instance Read PubKey where
    readPrec = parens $ do
        Ident "PubKey" <- lexP
        String str <- lexP
        maybe pfail return $ importPubKey =<< decodeHex str

instance IsString PubKey where
    fromString = fromMaybe e . (importPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Show PubKey where
    showsPrec d k = showParen (d > 10) $
        showString "PubKey " . shows (B16.encode $ exportPubKey True k)

instance Read Msg where
    readPrec = parens $ do
        Ident "Msg" <- lexP
        String str <- lexP
        maybe pfail return $ msg =<< decodeHex str

instance IsString Msg where
    fromString = fromMaybe e . (msg <=< decodeHex)  where
        e = error "Could not decode message from hex string"

instance Show Msg where
    showsPrec d m = showParen (d > 10) $
        showString "Msg " . shows (B16.encode $ getMsg m)

instance Read Sig where
    readPrec = parens $ do
        Ident "Sig" <- lexP
        String str <- lexP
        maybe pfail return $ importSig =<< decodeHex str

instance IsString Sig where
    fromString = fromMaybe e . (importSig <=< decodeHex) where
        e = error "Could not decode signature from hex string"

instance Show Sig where
    showsPrec d s = showParen (d > 10) $
        showString "Sig " . shows (B16.encode $ exportSig s)

recSigFromString :: String -> Maybe RecSig
recSigFromString str = do
    bs <- decodeHex str
    rs <- either (const Nothing) Just $ decode bs
    importCompactRecSig rs

instance Read RecSig where
    readPrec = parens $ do
        Ident "RecSig" <- lexP
        String str <- lexP
        maybe pfail return $ recSigFromString str

instance IsString RecSig where
    fromString = fromMaybe e . recSigFromString
      where
        e = error "Could not decode signature from hex string"

instance Show RecSig where
    showsPrec d s = showParen (d > 10) $
        showString "RecSig " . shows (B16.encode . encode $ exportCompactRecSig s)

instance Read SecKey where
    readPrec = parens $ do
        Ident "SecKey" <- lexP
        String str <- lexP
        maybe pfail return $ secKey =<< decodeHex str

instance IsString SecKey where
    fromString = fromMaybe e . (secKey <=< decodeHex) where
        e = error "Colud not decode secret key from hex string"

instance Show SecKey where
    showsPrec d k = showParen (d > 10) $
        showString "SecKey " . shows (B16.encode $ getSecKey k)

instance Read Tweak where
    readPrec = parens $ do
        Ident "Tweak" <- lexP
        String str <- lexP
        maybe pfail return $ tweak =<< decodeHex str

instance IsString Tweak where
    fromString = fromMaybe e . (tweak <=< decodeHex) where
        e = error "Could not decode tweak from hex string"

instance Show Tweak where
    showsPrec d k = showParen (d > 10) $
        showString "Tweak " . shows (B16.encode $ getTweak k)

instance Eq PubKey where
    fp1 == fp2 = getPubKey fp1 == getPubKey fp2

instance Eq Msg where
    fm1 == fm2 = getMsg fm1 == getMsg fm2

instance Eq Sig where
    fg1 == fg2 = exportCompactSig fg1 == exportCompactSig fg2

instance Eq RecSig where
    fg1 == fg2 = exportCompactRecSig fg1 == exportCompactRecSig fg2

instance Eq SecKey where
    fk1 == fk2 = getSecKey fk1 == getSecKey fk2

instance Eq Tweak where
    ft1 == ft2 = getTweak ft1 == getTweak ft2

-- | Import 32-byte 'ByteString' as 'Msg'.
msg :: ByteString -> Maybe Msg
msg bs
    | BS.length bs == 32 = unsafePerformIO $ do
        fp <- mallocForeignPtr
        withForeignPtr fp $ flip poke (Msg32 (toShort bs))
        return $ Just $ Msg fp
    | otherwise = Nothing

-- | Import 32-byte 'ByteString' as 'SecKey'.
secKey :: ByteString -> Maybe SecKey
secKey bs
    | BS.length bs == 32 = withContext $ \ctx -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p -> do
            poke p (SecKey32 (toShort bs))
            ecSecKeyVerify ctx p
        if isSuccess ret
            then return $ Just $ SecKey fp
            else return Nothing
    | otherwise = Nothing

-- | Convert signature to a normalized lower-S form. Boolean value 'True'
-- indicates that the signature changed, 'False' indicates that it was already
-- normal.
normalizeSig :: Sig -> (Sig, Bool)
normalizeSig (Sig fg) = withContext $ \ctx -> do
    fg' <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg -> withForeignPtr fg' $ \pg' ->
        ecdsaSignatureNormalize ctx pg' pg
    return (Sig fg', isSuccess ret)

-- | 32-Byte 'ByteString' as 'Tweak'.
tweak :: ByteString -> Maybe Tweak
tweak bs
    | BS.length bs == 32 = unsafePerformIO $ do
        fp <- mallocForeignPtr
        withForeignPtr fp $ flip poke (Tweak32 (toShort bs))
        return $ Just $ Tweak fp
    | otherwise = Nothing

-- | Get 32-byte secret key.
getSecKey :: SecKey -> ByteString
getSecKey (SecKey fk) =
    fromShort $ getSecKey32 $ unsafePerformIO $ withForeignPtr fk peek

-- Get 64-byte public key.
getPubKey :: PubKey -> ByteString
getPubKey (PubKey fp) =
    fromShort $ getPubKey64 $ unsafePerformIO $ withForeignPtr fp peek

-- | Get 32-byte message.
getMsg :: Msg -> ByteString
getMsg (Msg fm) =
    fromShort $ getMsg32 $ unsafePerformIO $ withForeignPtr fm peek

-- | Get 32-byte tweak.
getTweak :: Tweak -> ByteString
getTweak (Tweak ft) =
    fromShort $ getTweak32 $ unsafePerformIO $ withForeignPtr ft peek

-- | Import DER-encoded public key.
importPubKey :: ByteString -> Maybe PubKey
importPubKey bs =  withContext $ \ctx -> useByteString bs $ \(b, l) -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyParse ctx p b l
    if isSuccess ret then return $ Just $ PubKey fp else return Nothing

-- | Encode secret key as DER.  First argument 'True' for compressed output.
exportSecKey :: Bool -> SecKey -> ByteString
exportSecKey compress (SecKey fk) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> alloca $ \l -> allocaBytes 279 $ \o -> do
        poke l 279
        ret <- ecSecKeyExport ctx o l k c
        unless (isSuccess ret) $ error "could not export secret key"
        n <- peek l
        packByteString (o, n)
  where
    c = if compress then compressed else uncompressed

-- | Encode public key as DER. First argument 'True' for compressed output.
exportPubKey :: Bool -> PubKey -> ByteString
exportPubKey compress (PubKey pub) = withContext $ \ctx ->
    withForeignPtr pub $ \p -> alloca $ \l -> allocaBytes z $ \o -> do
        poke l (fromIntegral z)
        ret <- ecPubKeySerialize ctx o l p c
        unless (isSuccess ret) $ error "could not serialize public key"
        n <- peek l
        packByteString (o, n)
  where
    c = if compress then compressed else uncompressed
    z = if compress then 33 else 65

exportCompactSig :: Sig -> CompactSig
exportCompactSig (Sig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \pg -> alloca $ \pc -> do
        ret <- ecdsaSignatureSerializeCompact ctx pc pg
        unless (isSuccess ret) $ error "Could not obtain compact signature"
        peek pc

importCompactSig :: CompactSig -> Maybe Sig
importCompactSig c = withContext $ \ctx -> alloca $ \pc -> do
    poke pc c
    fg <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg -> ecdsaSignatureParseCompact ctx pg pc
    if isSuccess ret then return $ Just $ Sig fg else return Nothing

-- | Import DER-encoded signature.
importSig :: ByteString -> Maybe Sig
importSig bs = withContext $ \ctx ->
    useByteString bs $ \(b, l) -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> ecdsaSignatureParseDer ctx g b l
        if isSuccess ret then return $ Just $ Sig fg else return Nothing

-- | Relaxed DER parsing. Allows certain DER errors and violations.
laxImportSig :: ByteString -> Maybe Sig
laxImportSig bs = withContext $ \ctx ->
    useByteString bs $ \(b, l) -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> laxDerParse ctx g b l
        if isSuccess ret then return $ Just $ Sig fg else return Nothing

-- | Encode signature as strict DER.
exportSig :: Sig -> ByteString
exportSig (Sig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \g -> alloca $ \l -> allocaBytes 72 $ \o -> do
        poke l 72
        ret <- ecdsaSignatureSerializeDer ctx o l g
        unless (isSuccess ret) $ error "could not serialize signature"
        n <- peek l
        packByteString (o, n)

-- | Verify message signature. 'True' means that the signature is correct.
verifySig :: PubKey -> Sig -> Msg -> Bool
verifySig (PubKey fp) (Sig fg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr fg $ \g ->
        withForeignPtr fm $ \m -> isSuccess <$> ecdsaVerify ctx g m p

signMsg :: SecKey -> Msg -> Sig
signMsg (SecKey fk) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> ecdsaSign ctx g m k nullFunPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ Sig fg

derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey fk) = withContext $ \ctx -> withForeignPtr fk $ \k -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyCreate ctx p k
    unless (isSuccess ret) $ error "could not compute public key"
    return $ PubKey fp

-- | Add tweak to secret key.
tweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (SecKey fk) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            ecSecKeyTweakAdd ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Multiply secret key by tweak.
tweakMulSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (SecKey fk) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            ecSecKeyTweakMul ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
tweakAddPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (PubKey fp) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' ->  do
            pub <- peek p
            poke p' pub
            ecPubKeyTweakAdd ctx p' t
        if isSuccess ret then return $ Just $ PubKey fp' else return Nothing

-- | Multiply public key by tweak. Tweak is multiplied first by G to obtain a
-- point.
tweakMulPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakMulPubKey (PubKey fp) (Tweak ft) = withContext $ \ctx ->
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' ->  do
            pub <- peek p
            poke p' pub
            ecPubKeyTweakMul ctx p' t
        if isSuccess ret then return $ Just $ PubKey fp' else return Nothing

-- | Add multiple public keys together.
combinePubKeys :: [PubKey] -> Maybe PubKey
combinePubKeys pubs = withContext $ \ctx -> pointers [] pubs $ \ps ->
    allocaArray (length ps) $ \a -> do
        pokeArray a ps
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \p ->
            ecPubKeyCombine ctx p a (fromIntegral $ length ps)
        if isSuccess ret
            then return $ Just $ PubKey fp
            else return Nothing
  where
    pointers ps [] f = f ps
    pointers ps (PubKey fp : pubs') f =
        withForeignPtr fp $ \p -> pointers (p:ps) pubs' f

-- | Parse a compact ECDSA signature (64 bytes + recovery id).
importCompactRecSig :: CompactRecSig -> Maybe RecSig
importCompactRecSig cr =
  if getCompactRecSigV cr `notElem` [0,1,2,3]
  then Nothing
  else withContext $ \ctx -> alloca $ \pc -> do
    let
      c = CompactSig (getCompactRecSigR cr) (getCompactRecSigS cr)
      recid = fromIntegral $ getCompactRecSigV cr
    poke pc c
    fg <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg ->
        ecdsaRecoverableSignatureParseCompact ctx pg pc recid
    if isSuccess ret then return $ Just $ RecSig fg else return Nothing

-- | Serialize an ECDSA signature in compact format (64 bytes + recovery id).
exportCompactRecSig :: RecSig -> CompactRecSig
exportCompactRecSig (RecSig fg) = withContext $ \ctx ->
    withForeignPtr fg $ \pg -> alloca $ \pc -> alloca $ \pr -> do
        ret <- ecdsaRecoverableSignatureSerializeCompact ctx pc pr pg
        unless (isSuccess ret) $ error "Could not obtain compact signature"
        CompactSig r s <- peek pc
        v <- fromIntegral <$> peek pr
        return $ CompactRecSig r s v

-- | Convert a recoverable signature into a normal signature.
convertRecSig :: RecSig -> Sig
convertRecSig (RecSig frg) = withContext $ \ctx ->
    withForeignPtr frg $ \prg -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \pg ->
            ecdsaRecoverableSignatureConvert ctx pg prg
        unless (isSuccess ret) $
            error "Could not convert a recoverable signature"
        return $ Sig fg

-- | Create a recoverable ECDSA signature.
signRecMsg :: SecKey -> Msg -> RecSig
signRecMsg (SecKey fk) (Msg fm) = withContext $ \ctx ->
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g ->
            ecdsaSignRecoverable ctx g m k nullFunPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ RecSig fg

-- | Recover an ECDSA public key from a signature.
recover :: RecSig -> Msg -> Maybe PubKey
recover (RecSig frg) (Msg fm) = withContext $ \ctx ->
    withForeignPtr frg $ \prg -> withForeignPtr fm $ \pm -> do
        fp <- mallocForeignPtr
        ret <- withForeignPtr fp $ \pp -> ecdsaRecover ctx pp prg pm
        if isSuccess ret then return $ Just $ PubKey fp else return Nothing

instance Arbitrary Msg where
    arbitrary = gen_msg
      where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = (msg . BS.pack) <$> replicateM 32 arbitrary
        gen_msg = fromJust <$> valid_bs

instance Arbitrary SecKey where
    arbitrary = gen_key where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = (secKey . BS.pack) <$> replicateM 32 arbitrary
        gen_key = fromJust <$> valid_bs

instance Arbitrary PubKey where
    arbitrary = do
        key <- arbitrary
        return $ derivePubKey key
