{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveDataTypeable #-}
-- |
-- Module      : Network.Connection
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : portable
--
-- Simple connection abstraction
--
module Network.Connection
    (
    -- * Type for a connection
      Connection
    , connectionID
    , ConnectionParams(..)
    , TLSSettings(..)
    , SockSettings(..)

    -- * Exceptions
    , LineTooLong(..)

    -- * Library initialization
    , initConnectionContext
    , ConnectionContext

    -- * Connection operation
    , connectFromHandle
    , connectTo
    , connectionClose

    -- * Sending and receiving data
    , connectionGet
    , connectionGetChunk
    , connectionGetChunk'
    , connectionGetLine
    , connectionPut

    -- * TLS related operation
    , connectionSetSecure
    , connectionIsSecure
    ) where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Monad (join)
import qualified Control.Exception as E
import qualified System.IO.Error as E

import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLS

import System.X509 (getSystemCertificateStore)

import Network.Socks5
import qualified Network as N

import Data.Data
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Random.AESCtr as RNG

import System.IO
import qualified Data.Map as M

import Network.Connection.Types

type Manager = MVar (M.Map TLS.SessionID TLS.SessionData)

-- | This is the exception raised if we reached the user specified limit for
-- the line in ConnectionGetLine.
data LineTooLong = LineTooLong deriving (Show,Typeable)

instance E.Exception LineTooLong

connectionSessionManager :: Manager -> TLS.SessionManager
connectionSessionManager mvar = TLS.SessionManager
    { TLS.sessionResume     = \sessionID -> withMVar mvar (return . M.lookup sessionID)
    , TLS.sessionEstablish  = \sessionID sessionData ->
                               modifyMVar_ mvar (return . M.insert sessionID sessionData)
    , TLS.sessionInvalidate = \sessionID -> modifyMVar_ mvar (return . M.delete sessionID)
    }

-- | Initialize the library with shared parameters between connection.
initConnectionContext :: IO ConnectionContext
initConnectionContext = ConnectionContext <$> getSystemCertificateStore

makeTLSParams :: ConnectionContext -> TLSSettings -> TLS.Params
makeTLSParams cg ts@(TLSSettingsSimple {}) =
    TLS.defaultParamsClient
        { TLS.pConnectVersion    = TLS.TLS11
        , TLS.pAllowedVersions   = [TLS.TLS10,TLS.TLS11,TLS.TLS12]
        , TLS.pCiphers           = TLS.ciphersuite_all
        , TLS.pCertificates      = Nothing
        , TLS.onCertificatesRecv = if settingDisableCertificateValidation ts
                                       then TLS.certificateNoChecks
                                       else TLS.certificateChecks checks (globalCertificateStore cg)
        }
    where checks = TLS.defaultChecks Nothing
makeTLSParams _ (TLSSettings p) = p

withBackend :: (ConnectionBackend -> IO a) -> Connection -> IO a
withBackend f conn = readMVar (connectionBackend conn) >>= f

connectionNew :: ConnectionParams -> ConnectionBackend -> IO Connection
connectionNew p backend =
    Connection <$> newMVar backend
               <*> newMVar (Just B.empty)
               <*> pure (connectionHostname p, connectionPort p)

-- | Use an already established handle to create a connection object.
--
-- if the TLS Settings is set, it will do the handshake with the server.
-- The SOCKS settings have no impact here, as the handle is already established
connectFromHandle :: ConnectionContext
                  -> Handle
                  -> ConnectionParams
                  -> IO Connection
connectFromHandle cg h p = withSecurity (connectionUseSecure p)
    where withSecurity Nothing            = connectionNew p $ ConnectionStream h
          withSecurity (Just tlsSettings) = tlsEstablish h (makeTLSParams cg tlsSettings) >>= connectionNew p . ConnectionTLS

-- | connect to a destination using the parameter
connectTo :: ConnectionContext -- ^ The global context of this connection.
          -> ConnectionParams  -- ^ The parameters for this connection (where to connect, and such).
          -> IO Connection     -- ^ The new established connection on success.
connectTo cg cParams = do
        h <- conFct (connectionHostname cParams) (N.PortNumber $ connectionPort cParams)
        connectFromHandle cg h cParams
    where
        conFct = case connectionUseSocks cParams of
                      Nothing                       -> N.connectTo
                      Just (SockSettingsSimple h p) -> socksConnectTo h (N.PortNumber p)

-- | Put a block of data in the connection.
connectionPut :: Connection -> ByteString -> IO ()
connectionPut connection content = withBackend doWrite connection
    where doWrite (ConnectionStream h) = B.hPut h content >> hFlush h
          doWrite (ConnectionTLS ctx)  = TLS.sendData ctx $ L.fromChunks [content]

-- | Get some bytes from a connection.
--
-- The size argument is just the maximum that could be returned to the user.
-- The call will return as soon as there's data, even if there's less
-- than requested.  Hence, it behaves like 'B.hGetSome'.
--
-- On end of input, 'connectionGet' returns 0, but subsequent calls will throw
-- an 'E.isEOFError' exception.
connectionGet :: Connection -> Int -> IO ByteString
connectionGet conn size
  | size < 0  = fail "Network.Connection.connectionGet: size < 0"
  | size == 0 = return B.empty
  | otherwise = connectionGetChunkBase "connectionGet" conn $ B.splitAt size

-- | Get the next block of data from the connection.
connectionGetChunk :: Connection -> IO ByteString
connectionGetChunk conn =
    connectionGetChunkBase "connectionGetChunk" conn $ \s -> (s, B.empty)

-- | Like 'connectionGetChunk', but return the unused portion to the buffer,
-- where it will be the next chunk read.
connectionGetChunk' :: Connection -> (ByteString -> (a, ByteString)) -> IO a
connectionGetChunk' = connectionGetChunkBase "connectionGetChunk'"

connectionGetChunkBase :: String -> Connection -> (ByteString -> (a, ByteString)) -> IO a
connectionGetChunkBase loc conn f =
    modifyMVar (connectionBuffer conn) $ \m ->
        case m of
            Nothing -> throwEOF conn loc
            Just buf
              | B.null buf -> do
                  chunk <- withBackend getMoreData conn
                  if B.null chunk
                     then closeBuf chunk
                     else updateBuf chunk
              | otherwise ->
                  updateBuf buf
  where
    getMoreData (ConnectionTLS tlsctx) = TLS.recvData tlsctx
    getMoreData (ConnectionStream h)   = B.hGetSome h (16 * 1024)

    updateBuf buf = case f buf of (a, !buf') -> return (Just buf', a)
    closeBuf  buf = case f buf of (a, _buf') -> return (Nothing, a)

-- | Get the next line, using ASCII LF as the line terminator.
--
-- This throws an 'isEOFError' exception on end of input, and LineTooLong when
-- the number of bytes gathered is over the limit without a line terminator.
--
-- The actual line returned can be bigger than the limit specified, provided
-- that the last chunk returned by the underlaying backend contains a LF.
-- In another world only when we need more input and limit is reached that the
-- LineTooLong exception will be raised.
--
-- An end of file will be considered as a line terminator too, if line is
-- not empty.
connectionGetLine :: Int           -- ^ Maximum number of bytes before raising a LineTooLong exception
                  -> Connection    -- ^ Connection
                  -> IO ByteString -- ^ The received line with the LF trimmed
connectionGetLine limit conn = more (throwEOF conn loc) 0 id
  where
    loc = "connectionGetLine"
    lineTooLong = E.throwIO LineTooLong

    -- Accumulate chunks using a difference list, and concatenate them
    -- when an end-of-line indicator is reached.
    more eofK !currentSz !dl =
        getChunk (\s -> let len = B.length s
                         in if currentSz + len > limit
                               then lineTooLong
                               else more eofK (currentSz + len) (dl . (s:)))
                 (\s -> done (dl . (s:)))
                 (done dl)

    done :: ([ByteString] -> [ByteString]) -> IO ByteString
    done dl = return $! B.concat $ dl []

    -- Get another chunk, and call one of the continuations
    getChunk :: (ByteString -> IO r) -- moreK: need more input
             -> (ByteString -> IO r) -- doneK: end of line (line terminator found)
             -> IO r                 -- eofK:  end of file
             -> IO r
    getChunk moreK doneK eofK =
      join $ connectionGetChunkBase loc conn $ \s ->
        if B.null s
          then (eofK, B.empty)
          else case B.breakByte 10 s of
                 (a, b)
                   | B.null b  -> (moreK a, B.empty)
                   | otherwise -> (doneK a, B.tail b)

throwEOF :: Connection -> String -> IO a
throwEOF conn loc =
    E.throwIO $ E.mkIOError E.eofErrorType loc' Nothing (Just path)
  where
    loc' = "Network.Connection." ++ loc
    path = let (host, port) = connectionID conn
            in host ++ ":" ++ show port

-- | Close a connection.
connectionClose :: Connection -> IO ()
connectionClose = withBackend backendClose
    where backendClose (ConnectionTLS ctx)  = TLS.bye ctx >> TLS.contextClose ctx
          backendClose (ConnectionStream h) = hClose h

-- | Activate secure layer using the parameters specified.
--
-- This is typically used to negociate a TLS channel on an already
-- establish channel, e.g. supporting a STARTTLS command. it also
-- flush the received buffer to prevent application confusing
-- received data before and after the setSecure call.
--
-- If the connection is already using TLS, nothing else happens.
connectionSetSecure :: ConnectionContext
                    -> Connection
                    -> TLSSettings
                    -> IO ()
connectionSetSecure cg connection params =
    modifyMVar_ (connectionBuffer connection) $ \b ->
    modifyMVar (connectionBackend connection) $ \backend ->
        case backend of
            (ConnectionStream h) -> do ctx <- tlsEstablish h (makeTLSParams cg params)
                                       return (ConnectionTLS ctx, Just B.empty)
            (ConnectionTLS _)    -> return (backend, b)

-- | Returns if the connection is establish securely or not.
connectionIsSecure :: Connection -> IO Bool
connectionIsSecure conn = withBackend isSecure conn
    where isSecure (ConnectionStream _) = return False
          isSecure (ConnectionTLS _)    = return True

tlsEstablish :: Handle -> TLS.Params -> IO TLS.Context
tlsEstablish handle tlsParams = do
    rng <- RNG.makeSystem
    ctx <- TLS.contextNewOnHandle handle tlsParams rng
    TLS.handshake ctx
    return ctx
