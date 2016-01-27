import Test.Framework (defaultMain)

-- Some simple signing tests
import qualified Crypto.Secp256k1.Tests as T
import qualified Crypto.Secp256k1.Internal.Tests as I

main :: IO ()
main = defaultMain $ T.tests ++ I.tests
