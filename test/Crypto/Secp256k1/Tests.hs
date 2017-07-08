module Crypto.Secp256k1.Tests (tests) where

import           Crypto.Secp256k1
import           Data.Serialize
import qualified Data.ByteString.Base16               as B16
import qualified Data.ByteString.Char8                as B8
import           Data.Maybe                           (fromMaybe)
import           Data.String                          (fromString)
import           Data.String.Conversions              (cs)
import           Test.Framework                       (Test, testGroup)
import           Test.Framework.Providers.HUnit       (testCase)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.HUnit                           (Assertion, assertEqual)
import           Test.QuickCheck                      (Property, (==>))

tests :: [Test]
tests =
    [ testGroup "Signing"
        [ testProperty "Signing messages" signMsgTest
        , testProperty "Recoverably signing messages" signRecMsgTest
        , testProperty "Bad signatures" badSignatureTest
        , testProperty "Bad recoverable signatures" badRecSignatureTest
        , testProperty "Normalize signatures" normalizeSigTest
        , testProperty "Recover public keys" recoverTest
        , testProperty "Bad recover public keys" badRecoverTest
        ]
    , testGroup "Serialization"
        [ testProperty "Serialize public key" serializePubKeyTest
        , testProperty "Serialize DER signature" serializeSigTest
        , testProperty "Serialize lax DER signature" serializeLaxSigTest
        , testProperty "Serialize compact signature" serializeCompactSigTest
        , testProperty "Serialize compact recoverable signature" serializeCompactRecSigTest
        , testProperty "Serialize secret key" serializeSecKeyTest
        , testProperty "Show/Read public key" (showRead :: PubKey -> Bool)
        , testProperty "Show/Read secret key" (showRead :: SecKey -> Bool)
        , testProperty "Show/Read tweak" (showReadTweak :: SecKey -> Bool)
        , testProperty "Show/Read signature" (showReadSig :: (SecKey, Msg) -> Bool)
        , testProperty "Show/Read recoverable signature" (showReadRecSig :: (SecKey, Msg) -> Bool)
        , testProperty "Show/Read message" (showRead :: Msg -> Bool)
        , testProperty "String public key" isStringPubKey
        , testProperty "String secret key" isStringSecKey
        , testProperty "String signature" isStringSig
        , testProperty "String recoverable signature" isStringRecSig
        , testProperty "String message" isStringMsg
        , testProperty "String tweak" isStringTweak
        ]
    , testGroup "Tweaks"
        [ testCase "Tweak add secret key" tweakAddSecKeyTest
        , testCase "Tweak multiply secret key" tweakMulSecKeyTest
        , testCase "Tweak add public key" tweakAddPubKeyTest
        , testCase "Tweak multiply public key" tweakMulPubKeyTest
        , testCase "Combine public keys" combinePubKeyTest
        ]
    ]

isStringPubKey :: (PubKey, Bool) -> Bool
isStringPubKey (k, c) = k == fromString (cs hex) where
    hex = B16.encode $ exportPubKey c k

isStringSig :: (SecKey, Msg) -> Bool
isStringSig (k, m) = g == fromString (cs hex) where
    g = signMsg k m
    hex = B16.encode $ exportSig g

isStringRecSig :: (SecKey, Msg) -> Bool
isStringRecSig (k, m) = g == fromString (cs hex) where
    g = signRecMsg k m
    hex = B16.encode . encode $ exportCompactRecSig g

isStringMsg :: Msg -> Bool
isStringMsg m = m == fromString (cs m') where
    m' = B16.encode $ getMsg m

isStringSecKey :: SecKey -> Bool
isStringSecKey k = k == fromString (cs hex) where
    hex = B16.encode $ getSecKey k

isStringTweak :: SecKey -> Bool
isStringTweak k = t == fromString (cs hex) where
    t = fromMaybe e . tweak $ getSecKey k
    hex = B16.encode $ getTweak t
    e = error "Could not extract tweak from secret key"

showReadTweak :: SecKey -> Bool
showReadTweak k = showRead t where
    t = tweak $ getSecKey k

showReadSig :: (SecKey, Msg) -> Bool
showReadSig (k, m) = showRead sig where
    sig = signMsg k m

showReadRecSig :: (SecKey, Msg) -> Bool
showReadRecSig (k, m) = showRead recSig where
    recSig = signRecMsg k m

showRead :: (Show a, Read a, Eq a) => a -> Bool
showRead x = read (show x) == x

signMsgTest :: (Msg, SecKey) -> Bool
signMsgTest (fm, fk) = verifySig fp fg fm where
    fp = derivePubKey fk
    fg = signMsg fk fm

signRecMsgTest :: (Msg, SecKey) -> Bool
signRecMsgTest (fm, fk) = verifySig fp fg fm where
    fp = derivePubKey fk
    fg = convertRecSig $ signRecMsg fk fm

recoverTest :: (Msg, SecKey) -> Bool
recoverTest (fm, fk) = recover fg fm == Just fp where
    fp = derivePubKey fk
    fg = signRecMsg fk fm

badRecoverTest :: (Msg, SecKey, Msg) -> Property
badRecoverTest (fm, fk, fm') =
  fm' /= fm ==> fp' /= Nothing ==> fp' /= Just fp
  where
    fg  = signRecMsg fk fm
    fp  = derivePubKey fk
    fp' = recover fg fm'

badSignatureTest :: (Msg, SecKey, PubKey) -> Bool
badSignatureTest (fm, fk, fp) = not $ verifySig fp fg fm where
    fg = signMsg fk fm

badRecSignatureTest :: (Msg, SecKey, PubKey) -> Bool
badRecSignatureTest (fm, fk, fp) = not $ verifySig fp fg fm where
    fg = convertRecSig $ signRecMsg fk fm

normalizeSigTest :: (Msg, SecKey) -> Bool
normalizeSigTest (fm, fk) = not norm && sig == fg where
    fg = signMsg fk fm
    (sig, norm) = normalizeSig fg

serializePubKeyTest :: (PubKey, Bool) -> Bool
serializePubKeyTest (fp, b) =
    case importPubKey $ exportPubKey b fp of
        Just fp' -> fp == fp'
        Nothing -> False

serializeSigTest :: (Msg, SecKey) -> Bool
serializeSigTest (fm, fk) =
    case importSig $ exportSig fg of
        Just fg' -> fg == fg'
        Nothing -> False
  where
    fg = signMsg fk fm

serializeLaxSigTest :: (Msg, SecKey) -> Bool
serializeLaxSigTest (fm, fk) =
    case laxImportSig $ exportSig fg of
        Just fg' -> fg == fg'
        Nothing -> False
  where
    fg = signMsg fk fm

serializeCompactSigTest :: (Msg, SecKey) -> Bool
serializeCompactSigTest (fm, fk) =
    case importCompactSig $ exportCompactSig fg of
        Just fg' -> fg == fg'
        Nothing -> False
  where
    fg = signMsg fk fm

serializeCompactRecSigTest :: (Msg, SecKey) -> Bool
serializeCompactRecSigTest (fm, fk) =
    case importCompactRecSig $ exportCompactRecSig fg of
        Just fg' -> fg == fg'
        Nothing -> False
  where
    fg = signRecMsg fk fm

serializeSecKeyTest :: SecKey -> Bool
serializeSecKeyTest fk =
    case secKey $ getSecKey fk of
        Just fk' -> fk == fk'
        Nothing -> False

tweakAddSecKeyTest :: Assertion
tweakAddSecKeyTest =
    assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
        key <- secKey $ fst $ B16.decode $ B8.pack
            "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
        twk <- tweak $ fst $ B16.decode $ B8.pack
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        tweakAddSecKey key twk
    expected = secKey $ fst $ B16.decode $ B8.pack
        "ec1e3ce1cefa18a671d51125e2b249688d934b0e28f5d1665384d9b02f929059"

tweakMulSecKeyTest :: Assertion
tweakMulSecKeyTest =
    assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
        key <- secKey $ fst $ B16.decode $ B8.pack
            "f65255094d7773ed8dd417badc9fc045c1f80fdc5b2d25172b031ce6933e039a"
        twk <- tweak $ fst $ B16.decode $ B8.pack
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        tweakMulSecKey key twk
    expected = secKey $ fst $ B16.decode $ B8.pack
        "a96f5962493acb179f60a86a9785fc7a30e0c39b64c09d24fe064d9aef15e4c0"

tweakAddPubKeyTest :: Assertion
tweakAddPubKeyTest =
    assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
        pub <- importPubKey $ fst $ B16.decode $ B8.pack
            "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705\
            \12213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        twk <- tweak $ fst $ B16.decode $ B8.pack
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        tweakAddPubKey pub twk
    expected = importPubKey $ fst $ B16.decode $ B8.pack
        "04441c3982b97576646e0df0c96736063df6b42f2ee566d13b9f6424302d1379e518fd\
        \c87a14c5435bff7a5db4552042cb4120c6b86a4bbd3d0643f3c14ad01368"

tweakMulPubKeyTest :: Assertion
tweakMulPubKeyTest =
    assertEqual "tweaked keys match" expected tweaked
  where
    tweaked = do
        pub <- importPubKey $ fst $ B16.decode $ B8.pack
            "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705\
            \12213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        twk <- tweak $ fst $ B16.decode $ B8.pack
            "f5cbe7d88182a4b8e400f96b06128921864a18187d114c8ae8541b566c8ace00"
        tweakMulPubKey pub twk
    expected = importPubKey $ fst $ B16.decode $ B8.pack
        "04f379dc99cdf5c83e433defa267fbb3377d61d6b779c06a0e4ce29ae3ff5353b12ae4\
        \9c9d07e7368f2ba5a446c203255ce912322991a2d6a9d5d5761c61ed1845"

combinePubKeyTest :: Assertion
combinePubKeyTest =
    assertEqual "combined keys match" expected combined
  where
    combined = do
        pub1 <- importPubKey $ fst $ B16.decode $ B8.pack
            "04dded4203dac96a7e85f2c374a37ce3e9c9a155a72b64b4551b0bfe779dd44705\
            \12213d5ed790522c042dee8e85c4c0ec5f96800b72bc5940c8bc1c5e11e4fcbf"
        pub2 <- importPubKey $ fst $ B16.decode $ B8.pack
            "0487d82042d93447008dfe2af762068a1e53ff394a5bf8f68a045fa642b99ea5d1\
            \53f577dd2dba6c7ae4cfd7b6622409d7edd2d76dd13a8092cd3af97b77bd2c77"
        pub3 <- importPubKey $ fst $ B16.decode $ B8.pack
            "049b101edcbe1ee37ff6b2318526a425b629e823d7d8d9154417880595a28000ee\
            \3febd908754b8ce4e491aa6fe488b41fb5d4bb3788e33c9ff95a7a9229166d59"
        combinePubKeys [pub1, pub2, pub3]
    expected = importPubKey $ fst $ B16.decode $ B8.pack
        "043d9a7ec70011efc23c33a7e62d2ea73cca87797e3b659d93bea6aa871aebde56c3bc\
        \6134ca82e324b0ab9c0e601a6d2933afe7fb5d9f3aae900f5c5dc6e362c8"
