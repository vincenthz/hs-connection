-- |
-- Module      : Network.Connection.ChachaRNG
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE ForeignFunctionInterface #-}
module Network.Connection.ChachaRNG
    ( initialize
    , generate
    , ChachaRNG
    ) where

import Crypto.Random
import Data.SecureMem
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString as B
import Data.Byteable
import Data.Word
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.C.Types
import System.IO.Unsafe

instance CPRG ChachaRNG where
    cprgCreate entPool = initialize (grabEntropy 40 entPool)
    cprgGenerate = generate

-- | ChaCha context
newtype ChachaRNG = ChachaRNG SecureMem

-- | Initialize a new ChaCha context with the number of rounds,
-- the key and the nonce associated.
initialize :: Byteable seed
           => seed        -- ^ 40 bytes of seed
           -> ChachaRNG       -- ^ the initial ChaCha state
initialize seed
    | sLen /= 40 = error "ChaCha Random: seed length should be 40 bits"
    | otherwise = unsafePerformIO $ do
        stPtr <- createSecureMem 64 $ \stPtr ->
                    withBytePtr seed $ \seedPtr ->
                        ccryptonite_chacha_init (castPtr stPtr) seedPtr
        return $ ChachaRNG stPtr
  where sLen     = byteableLength seed

generate :: Int -> ChachaRNG -> (ByteString, ChachaRNG)
generate nbBytes st@(ChachaRNG prevSt)
    | nbBytes <= 0 = (B.empty, st)
    | otherwise    = unsafePerformIO $ do
        output <- B.mallocByteString nbBytes
        newSt  <- secureMemCopy prevSt
        withForeignPtr output $ \dstPtr ->
            withSecureMemPtr newSt $ \stPtr ->
                ccryptonite_chacha_random 8 dstPtr (castPtr stPtr) (fromIntegral nbBytes)
        return (B.PS output 0 nbBytes, ChachaRNG newSt)

foreign import ccall "connection_chacha_init"
    ccryptonite_chacha_init :: Ptr ChachaRNG -> Ptr Word8 -> IO ()

foreign import ccall "connection_chacha_random"
    ccryptonite_chacha_random :: Int -> Ptr Word8 -> Ptr ChachaRNG -> CUInt -> IO ()
