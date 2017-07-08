{-# LANGUAGE OverloadedStrings #-}
module Crypto.Secp256k1.Internal.Tests (tests) where

import           Control.Monad
import           Control.Monad.Trans
import           Crypto.Secp256k1.Internal
import           Data.ByteString                (ByteString, packCStringLen,
                                                 useAsCStringLen)
import qualified Data.ByteString.Base16         as B16
import           Data.ByteString.Short          (toShort)
import           Foreign
import           System.Entropy
import           Test.Framework                 (Test, testGroup)
import           Test.Framework.Providers.HUnit (testCase)
import           Test.HUnit                     (Assertion, assertBool,
                                                 assertEqual)

tests :: [Test]
tests =
    [ testGroup "Housekeeping"
        [ testCase "Create context"           createContextTest
        , testCase "Randomize context"        randomizeContextTest
        , testCase "Clone context"            cloneContextTest
        ]
    , testGroup "Serialization"
        [ testCase "Parse public key"         ecPubkeyParseTest
        , testCase "Serialize public key"     ecPubKeySerializeTest
        , testCase "Storable public key"      pubkeyStorableTest
        , testCase "Storable signature"       signatureStorableTest
        , testCase "Parse DER signature"      ecdsaSignatureParseDerTest
        , testCase "Lax parse DER signature"  laxDerParseTest
        , testCase "Serialize DER signature"  ecdsaSignatureSerializeDerTest
        ]
    , testGroup "Signatures"
        [ testCase "ECDSA verify"             ecdsaVerifyTest
        -- TODO:
        -- , testCase "RFC6979 nonce function"   nonce_function_rfc6979_test
        , testCase "ECDSA sign"               ecdsaSignTest
        ]
    , testGroup "Secret keys"
        [ testCase "Verify secret key"        ecSecKeyVerifyTest
        , testCase "Create public key"        ecPubkeyCreateTest
        , testCase "Tweak add secret key"     ecSecKeyTweakAddTest
        , testCase "Tweak mult. secret key"   ecSecKeyTweakMulTest
        ]
    , testGroup "Public keys"
        [ testCase "Tweak add public key"     ecPubKeyTweakAddTest
        , testCase "Tweak mult. public key"   ecPubKeyTweakMulTest
        , testCase "Combine public keys"      ecPubKeyCombineTest
        ]
    ]

withEntropy :: (Ptr Seed32 -> IO a) -> IO a
withEntropy f =
    getEntropy 32 >>= \e ->
    alloca $ \s ->
    poke s (Seed32 (toShort e)) >> f s

createContextTest :: Assertion
createContextTest = do
    context_ptr <- liftIO $ contextCreate signVerify
    assertBool "context not null" $ context_ptr /= nullPtr

randomizeContextTest :: Assertion
randomizeContextTest = do
    ret <- liftIO $ contextCreate sign >>= \x ->
        withEntropy (contextRandomize x)
    assertBool "context randomized" $ isSuccess ret

cloneContextTest :: Assertion
cloneContextTest = do
    (x1, x2) <- liftIO $ do
        x1 <- contextCreate signVerify
        ret <- withEntropy $ contextRandomize x1
        unless (isSuccess ret) $ error "failed to randomize context"
        x2 <- contextClone x1
        return (x1, x2)
    assertBool "original context not null" $ x1 /= nullPtr
    assertBool "cloned context not null" $ x2 /= nullPtr
    assertBool "context ptrs different" $ x1 /= x2

ecPubkeyParseTest :: Assertion
ecPubkeyParseTest = do
    ret <- liftIO $ useAsCStringLen der $ \(i, il) -> do
        x <- contextCreate verify
        alloca $ \pubkey ->
            ecPubKeyParse x pubkey (castPtr i) (fromIntegral il)
    assertBool "parsed public key" (isSuccess ret)
  where
    der = fst $ B16.decode
        "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"

ecPubKeySerializeTest :: Assertion
ecPubKeySerializeTest = do
    (ret, dec) <- liftIO $ useAsCStringLen der $ \(i, il) ->
        alloca $ \k -> alloca $ \ol -> allocaBytes 72 $ \o -> do
        poke ol 72
        x <- contextCreate verify
        ret1 <-
            ecPubKeyParse x k (castPtr i) (fromIntegral il)
        unless (isSuccess ret1) $ error "failed to parse pubkey"
        ret2 <- ecPubKeySerialize
            x o ol k compressed
        len <- fromIntegral <$> peek ol
        decoded <- packCStringLen (castPtr o, len)
        return (ret2, decoded)
    assertBool  "serialized public key successfully" $ isSuccess ret
    assertEqual "public key matches" der dec
  where
    der = fst $ B16.decode
        "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"

pubkeyStorableTest :: Assertion
pubkeyStorableTest = do
    (pk1, pk2, dec) <- liftIO $ useAsCStringLen der $ \(i, il) -> do
        x <- contextCreate verify
        pk1 <- alloca $ \pk -> do
            ret <-
                ecPubKeyParse x pk (castPtr i) (fromIntegral il)
            unless (isSuccess ret) $ error "failed to parse pubkey"
            peek pk
        (pk2, dec) <- alloca $ \pk -> alloca $ \ol -> allocaBytes 72 $ \o -> do
            poke ol 72
            poke pk pk1
            ret <-
                ecPubKeySerialize x o ol pk compressed
            unless (isSuccess ret) $ error "failed to serialize pubkey"
            len <- fromIntegral <$> peek ol
            dec <- packCStringLen (castPtr o, len)
            pk2 <- peek pk
            return (pk2, dec)
        return (pk1, pk2, dec)
    assertEqual "poke/peek public key" pk1 pk2
    assertEqual "public key matches" der dec
  where
    der = fst $ B16.decode
        "03dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705"

signatureStorableTest :: Assertion
signatureStorableTest = do
    (sig, ret) <- liftIO $ do
        x <- contextCreate verify
        g <- alloca $ \pc -> alloca $ \pg -> do
            poke pc cpt
            ret <- ecdsaSignatureParseCompact x pg (castPtr pc)
            unless (isSuccess ret) $ error "failed to parse signature"
            peek pg
        alloca $ \pc -> alloca $ \pg -> do
            poke pg g
            ret <- ecdsaSignatureSerializeCompact x pc pg
            c <- peek pc
            return (c, ret)
    assertBool "successful serialization" (isSuccess ret)
    assertEqual "signatures match" cpt sig
  where
    cpt = CompactSig
        (toShort $ fst $ B16.decode "f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37fb22")
        (toShort $ fst $ B16.decode "6f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e3045")

ecdsaSignatureParseDerTest :: Assertion
ecdsaSignatureParseDerTest = do
    ret <- liftIO $ useAsCStringLen der $ \(d, dl) -> alloca $ \s -> do
        x <- contextCreate verify
        ecdsaSignatureParseDer x s (castPtr d) (fromIntegral dl)
    assertBool "parsed signature successfully" $ isSuccess ret
  where
    der = fst $ B16.decode
        "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
        \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
        \45"

laxDerParseTest :: Assertion
laxDerParseTest = do
    ret <- liftIO $ useAsCStringLen der $ \(d, dl) -> alloca $ \s -> do
        x <- contextCreate verify
        laxDerParse x s (castPtr d) (fromIntegral dl)
    assertBool "parsed signature successfully" $ isSuccess ret
  where
    der = fst $ B16.decode
        "30450220f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37fb\
        \2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e3045"

parseDer :: Ptr Ctx -> ByteString -> IO Sig64
parseDer x bs = useAsCStringLen bs $ \(d, dl) -> alloca $ \s -> do
    ret <- ecdsaSignatureParseDer x s (castPtr d) (fromIntegral dl)
    unless (isSuccess ret) $ error "could not parse DER"
    peek s

ecdsaSignatureSerializeDerTest :: Assertion
ecdsaSignatureSerializeDerTest = do
    (ret, enc) <- liftIO $ do
        x <- contextCreate verify
        sig <- parseDer x der
        alloca $ \s -> alloca $ \ol -> allocaBytes 72 $ \o -> do
            poke ol 72
            poke s sig
            ret <-
                ecdsaSignatureSerializeDer x o ol s
            len <- fromIntegral <$> peek ol
            enc <- packCStringLen (castPtr o, len)
            return (ret, enc)
    assertBool  "serialization successful" $ isSuccess ret
    assertEqual "signatures match" der enc
  where
    der = fst $ B16.decode
        "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
        \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
        \45"

ecdsaVerifyTest :: Assertion
ecdsaVerifyTest = do
    ret <- liftIO $ do
        x <- contextCreate verify
        sig <- parseDer x der
        pk <- useAsCStringLen pub $ \(p, pl) -> alloca $ \k -> do
            ret <-
                ecPubKeyParse x k (castPtr p) (fromIntegral pl)
            unless (isSuccess ret) $ error "could not parse public key"
            peek k
        alloca $ \m -> alloca $ \k -> alloca $ \s -> do
            poke m msg
            poke k pk
            poke s sig
            ecdsaVerify x s m k
    assertBool "signature valid" $ isSuccess ret
  where
    der = fst $ B16.decode
        "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
        \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
        \45"
    pub = fst $ B16.decode
        "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
        \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    msg = Msg32 $ toShort $ fst $ B16.decode
        "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"

signCtx :: IO (Ptr Ctx)
signCtx = contextCreate sign >>= \c ->
    withEntropy (contextRandomize c) >>= \r ->
        unless (isSuccess r) (error "failed to randomize context") >> return c

ecdsaSignTest :: Assertion
ecdsaSignTest = do
    (ret, sig) <- liftIO $ do
        x <- signCtx
        alloca $ \s -> alloca $ \m -> alloca $ \k -> alloca $ \ol ->
            allocaBytes 72 $ \o -> do
                poke ol 72
                poke m msg
                poke k key
                ret1 <-
                    -- TODO:
                    -- ecdsaSign x s m k nonce_function_default nullPtr
                    ecdsaSign x s m k nullFunPtr nullPtr
                ret2 <- ecdsaSignatureSerializeDer x o ol s
                unless (isSuccess ret2) $ error "could not serialize signature"
                len <- peek ol
                sig <- packCStringLen (castPtr o, fromIntegral len)
                return (ret1, sig)
    assertBool "successful signing" $ isSuccess ret
    assertEqual "signature matches" sig der
  where
    msg = Msg32 $ toShort $ fst $ B16.decode
        "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    key = SecKey32 $ toShort $ fst $ B16.decode
        "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    der = fst $ B16.decode
        "3045022100f502bfa07af43e7ef265618b0d929a7619ee01d6150e37eb6eaaf2c8bd37\
        \fb2202206f0415ab0e9a977afd78b2c26ef39b3952096d319fd4b101c768ad6c132e30\
        \45"

ecSecKeyVerifyTest :: Assertion
ecSecKeyVerifyTest = do
    ret <- liftIO $ alloca $ \k -> do
        poke k key
        x <- signCtx
        ecSecKeyVerify x k
    assertBool "valid secret key" $ isSuccess ret
  where
    key = SecKey32 $ toShort $ fst $ B16.decode
        "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"

ecPubkeyCreateTest :: Assertion
ecPubkeyCreateTest = do
    (ret, pk) <- liftIO $ alloca $ \p -> alloca $ \k -> do
        poke k key
        x <- signCtx
        ret <- ecPubKeyCreate x p k
        allocaBytes 65 $ \o -> alloca $ \ol -> do
            poke ol 65
            rets <- ecPubKeySerialize
                x o ol p uncompressed
            unless (isSuccess rets) $ error "failed to serialive public key"
            len <- fromIntegral <$> peek ol
            pk <- packCStringLen (castPtr o, len)
            return (ret, pk)
    assertBool "successful pubkey creation" $ isSuccess ret
    assertEqual "public key matches" pub pk
  where
    key = SecKey32 $ toShort $ fst $ B16.decode
        "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    pub = fst $ B16.decode
        "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
        \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"

ecSecKeyTweakAddTest :: Assertion
ecSecKeyTweakAddTest = do
    (ret, tweaked) <- liftIO $ do
        x <- signCtx
        alloca $ \w -> alloca $ \k -> do
            poke w tweak
            poke k key
            ret <- ecSecKeyTweakAdd x k w
            tweaked <- peek k
            return (ret, tweaked)
    assertBool "successful secret key tweak" $ isSuccess ret
    assertEqual "tweaked keys match" expected tweaked
  where
    key = SecKey32 $ toShort $ fst $ B16.decode
        "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    tweak = Tweak32 $ toShort $ fst $ B16.decode
        "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected = SecKey32 $ toShort $ fst $ B16.decode
        "ec1e3ce1cefa18a671d51125e2b249688d934b0e28f5d1665384d9b02f929059"

ecSecKeyTweakMulTest :: Assertion
ecSecKeyTweakMulTest = do
    (ret, tweaked) <- liftIO $ do
        x <- contextCreate sign
        retr <- withEntropy $ contextRandomize x
        unless (isSuccess retr) $ error "failed to randomize context"
        alloca $ \w -> alloca $ \k -> do
            poke w tweak
            poke k key
            ret <- ecSecKeyTweakMul x k w
            tweaked <- peek k
            return (ret, tweaked)
    assertBool "successful secret key tweak" $ isSuccess ret
    assertEqual "tweaked keys match" expected tweaked
  where
    key = SecKey32 $ toShort $ fst $ B16.decode
        "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
    tweak = Tweak32 $ toShort $ fst $ B16.decode
        "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected = SecKey32 $ toShort $ fst $ B16.decode
        "a96f5962493acb179f60a86a9785fc7a30e0c39b64c09d24fe064d9aef15e4c0"

serializeKey :: Ptr Ctx -> Ptr PubKey64 -> IO ByteString
serializeKey x p = allocaBytes 72 $ \d -> alloca $ \dl -> do
    poke dl 72
    ret <- ecPubKeySerialize x d dl p uncompressed
    unless (isSuccess ret) $ error "could not serialize public key"
    len <- peek dl
    packCStringLen (castPtr d, fromIntegral len)

parseKey :: Ptr Ctx -> ByteString -> IO PubKey64
parseKey x bs = alloca $ \p -> useAsCStringLen bs $ \(d, dl) -> do
    ret <- ecPubKeyParse x p (castPtr d) (fromIntegral dl)
    unless (isSuccess ret) $ error "could not parse public key"
    peek p

ecPubKeyTweakAddTest :: Assertion
ecPubKeyTweakAddTest = do
    (ret, tweaked) <- liftIO $ do
        x <- contextCreate verify
        pk <- parseKey x pub
        alloca $ \w -> alloca $ \p -> do
            poke w tweak
            poke p pk
            ret <- ecPubKeyTweakAdd x p w
            tweaked <- serializeKey x p
            return (ret, tweaked)
    assertBool "successful secret key tweak" $ isSuccess ret
    assertEqual "tweaked keys match" expected tweaked
  where
    pub = fst $ B16.decode
        "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
        \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    tweak = Tweak32 $ toShort $ fst $ B16.decode
        "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected = fst $ B16.decode
        "04441c3982b97576646e0df0c96736063df6b42f2ee566d13b9f6424302d1379e518fd\
        \c87a14c5435bff7a5db4552042cb4120c6b86a4bbd3d0643f3c14ad01368"

ecPubKeyTweakMulTest :: Assertion
ecPubKeyTweakMulTest = do
    (ret, tweaked) <- liftIO $ do
        x <- contextCreate verify
        pk <- parseKey x pub
        alloca $ \w -> alloca $ \p -> do
            poke w tweak
            poke p pk
            ret <- ecPubKeyTweakMul x p w
            tweaked <- serializeKey x p
            return (ret, tweaked)
    assertBool "successful secret key tweak" $ isSuccess ret
    assertEqual "tweaked keys match" expected tweaked
  where
    pub = fst $ B16.decode
        "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
        \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    tweak = Tweak32 $ toShort $ fst $ B16.decode
        "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
    expected = fst $ B16.decode
        "04f379dc99cdf5c83e433defa267fbb3377d61d6b779c06a0e4ce29ae3ff5353b12ae4\
        \9c9d07e7368f2ba5a446c203255ce912322991a2d6a9d5d5761c61ed1845"

ecPubKeyCombineTest :: Assertion
ecPubKeyCombineTest = do
    (ret, com) <- liftIO $ alloca $ \p1 -> alloca $ \p2 -> alloca $ \p3 ->
        allocaArray 3 $ \a -> alloca $ \p -> do
            x <- contextCreate verify
            parse x pub1 p1
            parse x pub2 p2
            parse x pub3 p3
            pokeArray a [p1, p2, p3]
            ret <- ecPubKeyCombine x p a 3
            com <- serializeKey x p
            return (ret, com)
    assertBool "successful key combination" $ isSuccess ret
    assertEqual "combined keys match" expected com
  where
    parse x pub p = useAsCStringLen pub $ \(d, dl) -> do
        ret <- ecPubKeyParse x p (castPtr d) (fromIntegral dl)
        unless (isSuccess ret) $ error "could not parse public key"
    pub1 = fst $ B16.decode
        "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd447051221\
        \3d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
    pub2 = fst $ B16.decode
        "0487d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d153f5\
        \77dd2dba6c7ae4cfd7b6622409d7edd2d76dd13a8092cd3af97b77bd2c77"
    pub3 = fst $ B16.decode
        "049b101edcbe1ee37ff6b2318526a425b629e823d7d8d9154417880595a28000ee3feb\
        \d908754b8ce4e491aa6fe488b41fb5d4bb3788e33c9ff95a7a9229166d59"
    expected = fst $ B16.decode
        "043d9a7ec70011efc23c33a7e62d2ea73cca87797e3b659d93bea6aa871aebde56c3bc\
        \6134ca82e324b0ab9c0e601a6d2933afe7fb5d9f3aae900f5c5dc6e362c8"
