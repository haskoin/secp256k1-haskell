import           Control.Monad
import           Distribution.PackageDescription
import           Distribution.Simple
import           Distribution.Simple.LocalBuildInfo
import           Distribution.Simple.Setup
import           Distribution.Simple.Utils
import           Distribution.Verbosity
import           System.Environment
import           System.Exit

main :: IO ()
main = defaultMainWithHooks autoconfUserHooks
    { preConf = autogen
    , postConf = configure
    , preBuild = make
    , preClean = clean
    }

runInRepo :: Verbosity
            -> FilePath
            -> [String]
            -> Maybe [(String, String)]
            -> IO ExitCode
runInRepo v prog args envM = rawSystemIOWithEnv v
    prog args (Just "secp256k1") envM Nothing Nothing Nothing

autogen :: Args -> ConfigFlags -> IO HookedBuildInfo
autogen _ flags = do
    maybeExit $ runInRepo v "sh" ["./autogen.sh"] Nothing
    return emptyHookedBuildInfo
  where
    v = fromFlag $ configVerbosity flags

configure :: Args -> ConfigFlags -> PackageDescription -> LocalBuildInfo -> IO ()
configure args flags pd lbi = do
    (ccProg, ccFlags) <- configureCCompiler v programConfig
    env <- getEnvironment
    let env' = appendToEnvironment ("CFLAGS", unwords ccFlags) env
        args' = args ++ ["--with-gcc=" ++ ccProg]
    maybeExit $ runInRepo v "sh" args' (Just env')
  where
    args = "./configure" : "--enable-module-recovery" : configureArgs False flags
    v = fromFlag $ configVerbosity flags
    appendToEnvironment (key, val) [] = [(key, val)]
    appendToEnvironment (key, val) (kv@(k, v) : rest)
        | key == k  = (key, v ++ " " ++ val) : rest
        | otherwise = kv : appendToEnvironment (key, val) rest
    programConfig = withPrograms lbi

make :: Args -> BuildFlags -> IO HookedBuildInfo
make _ flags = do
    runInRepo v "make" ["clean"] Nothing
    runInRepo v "make" ["src/ecmult_static_context.h"] Nothing
    return emptyHookedBuildInfo
  where
    v = fromFlag $ buildVerbosity flags

clean :: Args -> CleanFlags -> IO HookedBuildInfo
clean _ flags = do
    runInRepo v "make" ["clean"] Nothing
    return emptyHookedBuildInfo
  where
    v = fromFlag $ cleanVerbosity flags
