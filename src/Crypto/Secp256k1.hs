{-# LANGUAGE CPP                   #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-|
Module      : Crypto.Secp256k1
License     : UNLICENSE
Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
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
    , exportSig
    -- ** Compact
    , CompactSig(..)
    , exportCompactSig
    , importCompactSig

    -- * Addition & Multiplication
    , Tweak
    , tweak
    , getTweak
    , tweakAddSecKey
    , tweakMulSecKey
    , tweakAddPubKey
    , tweakMulPubKey
    , combinePubKeys
    , tweakNegate
    ) where

import           Control.Monad             (replicateM, unless, (<=<))
import           Data.ByteString           (ByteString)
import qualified Data.ByteString           as BS
import qualified Data.ByteString.Base16    as B16
import           Data.ByteString.Short     (fromShort, toShort)
import           Data.Hashable             (Hashable (..))
import           Data.Maybe                (fromJust, fromMaybe, isJust)
import           Data.String               (IsString (..))
import           Data.String.Conversions   (ConvertibleStrings, cs)
import           Foreign                   (ForeignPtr, alloca, allocaArray,
                                            allocaBytes, mallocForeignPtr,
                                            nullPtr, peek, poke, pokeArray,
                                            withForeignPtr)
import           System.IO.Unsafe          (unsafePerformIO)
import           Test.QuickCheck           (Arbitrary (..),
                                            arbitraryBoundedRandom, suchThat)
import           Text.Read                 (Lexeme (String), lexP, parens,
                                            pfail, readPrec)

import           Control.DeepSeq
import           Crypto.Secp256k1.Internal

newtype PubKey = PubKey (ForeignPtr PubKey64)
newtype Msg = Msg (ForeignPtr Msg32)
newtype Sig = Sig (ForeignPtr Sig64)
newtype SecKey = SecKey (ForeignPtr SecKey32)
newtype Tweak = Tweak (ForeignPtr Tweak32)
newtype RecSig = RecSig (ForeignPtr RecSig65)

instance NFData PubKey where
    rnf (PubKey p) = p `seq` ()

instance NFData Msg where
    rnf (Msg p) = p `seq` ()

instance NFData Sig where
    rnf (Sig p) = p `seq` ()

instance NFData SecKey where
    rnf (SecKey p) = p `seq` ()

instance NFData Tweak where
    rnf (Tweak p) = p `seq` ()

instance NFData RecSig where
    rnf (RecSig p) = p `seq` ()

decodeHex :: ConvertibleStrings a ByteString => a -> Maybe ByteString
decodeHex str = if BS.null r then Just bs else Nothing where
    (bs, r) = B16.decode $ cs str

instance Read PubKey where
    readPrec = do
        String str <- lexP
        maybe pfail return $ importPubKey =<< decodeHex str

instance Hashable PubKey where
    i `hashWithSalt` k = i `hashWithSalt` exportPubKey True k

instance IsString PubKey where
    fromString = fromMaybe e . (importPubKey <=< decodeHex) where
        e = error "Could not decode public key from hex string"

instance Show PubKey where
    showsPrec _ = shows . B16.encode . exportPubKey True

instance Read Msg where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ msg =<< decodeHex str

instance Hashable Msg where
    i `hashWithSalt` m = i `hashWithSalt` getMsg m

instance IsString Msg where
    fromString = fromMaybe e . (msg <=< decodeHex)  where
        e = error "Could not decode message from hex string"

instance Show Msg where
    showsPrec _ = shows . B16.encode . getMsg

instance Read Sig where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ importSig =<< decodeHex str

instance IsString Sig where
    fromString = fromMaybe e . (importSig <=< decodeHex) where
        e = error "Could not decode signature from hex string"

instance Hashable Sig where
    i `hashWithSalt` s = i `hashWithSalt` exportSig s

instance Show Sig where
    showsPrec _ = shows . B16.encode . exportSig

instance Read SecKey where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ secKey =<< decodeHex str

instance Hashable SecKey where
    i `hashWithSalt` k = i `hashWithSalt` getSecKey k

instance IsString SecKey where
    fromString = fromMaybe e . (secKey <=< decodeHex) where
        e = error "Colud not decode secret key from hex string"

instance Show SecKey where
    showsPrec _ = shows . B16.encode . getSecKey

instance Hashable Tweak where
    i `hashWithSalt` t = i `hashWithSalt` getTweak t

instance Read Tweak where
    readPrec = parens $ do
        String str <- lexP
        maybe pfail return $ tweak =<< decodeHex str

instance IsString Tweak where
    fromString = fromMaybe e . (tweak <=< decodeHex) where
        e = error "Could not decode tweak from hex string"

instance Show Tweak where
    showsPrec _ = shows . B16.encode . getTweak

instance Eq PubKey where
    fp1 == fp2 = getPubKey fp1 == getPubKey fp2

instance Eq Msg where
    fm1 == fm2 = getMsg fm1 == getMsg fm2

instance Eq Sig where
    fg1 == fg2 = exportCompactSig fg1 == exportCompactSig fg2

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
    | BS.length bs == 32 = unsafePerformIO $ do
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
normalizeSig (Sig fg) = unsafePerformIO $ do
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
importPubKey bs =  unsafePerformIO $ useByteString bs $ \(b, l) -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyParse ctx p b l
    if isSuccess ret then return $ Just $ PubKey fp else return Nothing

-- | Encode public key as DER. First argument 'True' for compressed output.
exportPubKey :: Bool -> PubKey -> ByteString
exportPubKey compress (PubKey pub) = unsafePerformIO $
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
exportCompactSig (Sig fg) = unsafePerformIO $
    withForeignPtr fg $ \pg -> alloca $ \pc -> do
        ret <- ecdsaSignatureSerializeCompact ctx pc pg
        unless (isSuccess ret) $ error "Could not obtain compact signature"
        peek pc

importCompactSig :: CompactSig -> Maybe Sig
importCompactSig c = unsafePerformIO $ alloca $ \pc -> do
    poke pc c
    fg <- mallocForeignPtr
    ret <- withForeignPtr fg $ \pg -> ecdsaSignatureParseCompact ctx pg pc
    if isSuccess ret then return $ Just $ Sig fg else return Nothing

-- | Import DER-encoded signature.
importSig :: ByteString -> Maybe Sig
importSig bs = unsafePerformIO $
    useByteString bs $ \(b, l) -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> ecdsaSignatureParseDer ctx g b l
        if isSuccess ret then return $ Just $ Sig fg else return Nothing

-- | Encode signature as strict DER.
exportSig :: Sig -> ByteString
exportSig (Sig fg) = unsafePerformIO $
    withForeignPtr fg $ \g -> alloca $ \l -> allocaBytes 72 $ \o -> do
        poke l 72
        ret <- ecdsaSignatureSerializeDer ctx o l g
        unless (isSuccess ret) $ error "could not serialize signature"
        n <- peek l
        packByteString (o, n)

-- | Verify message signature. 'True' means that the signature is correct.
verifySig :: PubKey -> Sig -> Msg -> Bool
verifySig (PubKey fp) (Sig fg) (Msg fm) = unsafePerformIO $
    withForeignPtr fp $ \p -> withForeignPtr fg $ \g ->
        withForeignPtr fm $ \m -> isSuccess <$> ecdsaVerify ctx g m p

signMsg :: SecKey -> Msg -> Sig
signMsg (SecKey fk) (Msg fm) = unsafePerformIO $
    withForeignPtr fk $ \k -> withForeignPtr fm $ \m -> do
        fg <- mallocForeignPtr
        ret <- withForeignPtr fg $ \g -> ecdsaSign ctx g m k nullPtr nullPtr
        unless (isSuccess ret) $ error "could not sign message"
        return $ Sig fg

derivePubKey :: SecKey -> PubKey
derivePubKey (SecKey fk) = unsafePerformIO $ withForeignPtr fk $ \k -> do
    fp <- mallocForeignPtr
    ret <- withForeignPtr fp $ \p -> ecPubKeyCreate ctx p k
    unless (isSuccess ret) $ error "could not compute public key"
    return $ PubKey fp


-- | Add tweak to secret key.
tweakAddSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakAddSecKey (SecKey fk) (Tweak ft) = unsafePerformIO $
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            ecSecKeyTweakAdd ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Multiply secret key by tweak.
tweakMulSecKey :: SecKey -> Tweak -> Maybe SecKey
tweakMulSecKey (SecKey fk) (Tweak ft) = unsafePerformIO $
    withForeignPtr fk $ \k -> withForeignPtr ft $ \t -> do
        fk' <- mallocForeignPtr
        ret <- withForeignPtr fk' $ \k' ->  do
            key <- peek k
            poke k' key
            ecSecKeyTweakMul ctx k' t
        if isSuccess ret then return $ Just $ SecKey fk' else return Nothing

-- | Add tweak to public key. Tweak is multiplied first by G to obtain a point.
tweakAddPubKey :: PubKey -> Tweak -> Maybe PubKey
tweakAddPubKey (PubKey fp) (Tweak ft) = unsafePerformIO $
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
tweakMulPubKey (PubKey fp) (Tweak ft) = unsafePerformIO $
    withForeignPtr fp $ \p -> withForeignPtr ft $ \t -> do
        fp' <- mallocForeignPtr
        ret <- withForeignPtr fp' $ \p' ->  do
            pub <- peek p
            poke p' pub
            ecPubKeyTweakMul ctx p' t
        if isSuccess ret then return $ Just $ PubKey fp' else return Nothing

-- | Add multiple public keys together.
combinePubKeys :: [PubKey] -> Maybe PubKey
combinePubKeys [] = Nothing
combinePubKeys pubs = unsafePerformIO $ pointers [] pubs $ \ps ->
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

tweakNegate :: Tweak -> Maybe Tweak
tweakNegate (Tweak fk) = unsafePerformIO $ do
    fnew <- mallocForeignPtr
    peeked <- withForeignPtr fk peek
    ret <- withForeignPtr fnew $ \n -> do
        poke n peeked
        ecTweakNegate ctx n
    return $
        if isSuccess ret
            then Just (Tweak fnew)
            else Nothing

instance Arbitrary Msg where
    arbitrary = gen_msg
      where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = msg . BS.pack <$> replicateM 32 arbitraryBoundedRandom
        gen_msg = fromJust <$> valid_bs

instance Arbitrary SecKey where
    arbitrary = gen_key where
        valid_bs = bs_gen `suchThat` isJust
        bs_gen = secKey . BS.pack <$> replicateM 32 arbitraryBoundedRandom
        gen_key = fromJust <$> valid_bs

instance Arbitrary PubKey where
    arbitrary = derivePubKey <$> arbitrary
