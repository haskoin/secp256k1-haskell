{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE NoFieldSelectors #-}

-- |
-- Module      : Crypto.Secp256k1.Internal.Context
-- License     : UNLICENSE
-- Maintainer  : Jean-Pierre Rupp <jprupp@protonmail.ch>
-- Stability   : experimental
-- Portability : POSIX
--
-- The API for this module may change at any time. This is an internal module only
-- exposed for hacking and experimentation.
module Crypto.Secp256k1.Internal.Context where

import Control.Exception (bracket)
import Control.Monad (unless)
import Crypto.Secp256k1.Internal.ForeignTypes (CtxFlags, LCtx, Ret, Seed32, isSuccess)
import Crypto.Secp256k1.Internal.Util (withRandomSeed)
import Foreign (FunPtr, Ptr)
import Foreign.C (CInt (..), CString, CUInt (..))
import System.IO.Unsafe (unsafePerformIO)

newtype Ctx = Ctx {get :: Ptr LCtx}

randomizeContext :: Ctx -> IO ()
randomizeContext (Ctx ctx) = do
  ret <- withRandomSeed $ contextRandomize ctx
  unless (isSuccess ret) $ error "Could not randomize context"

createContext :: IO Ctx
createContext = Ctx <$> contextCreate signVerify

cloneContext :: Ctx -> IO Ctx
cloneContext = fmap Ctx . contextClone . (.get)

destroyContext :: Ctx -> IO ()
destroyContext = contextDestroy . (.get)

withContext :: (Ctx -> IO a) -> IO a
withContext = bracket create destroy
  where
    create = do
      ctx <- createContext
      randomizeContext ctx
      return ctx
    destroy = destroyContext

verify :: CtxFlags
verify = 0x0101

sign :: CtxFlags
sign = 0x0201

signVerify :: CtxFlags
signVerify = 0x0301

foreign import ccall safe "secp256k1.h secp256k1_context_create"
  contextCreate ::
    CtxFlags ->
    IO (Ptr LCtx)

foreign import ccall safe "secp256k1.h secp256k1_context_clone"
  contextClone ::
    Ptr LCtx ->
    IO (Ptr LCtx)

foreign import ccall safe "secp256k1.h secp256k1_context_destroy"
  contextDestroy ::
    Ptr LCtx ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_set_illegal_callback"
  setIllegalCallback ::
    Ptr LCtx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_set_error_callback"
  setErrorCallback ::
    Ptr LCtx ->
    -- | message, data
    FunPtr (CString -> Ptr a -> IO ()) ->
    -- | data
    Ptr a ->
    IO ()

foreign import ccall safe "secp256k1.h secp256k1_context_randomize"
  contextRandomize ::
    Ptr LCtx ->
    Ptr Seed32 ->
    IO Ret
