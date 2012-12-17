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
    , connectionPut

    -- * TLS related operation
    , connectionSetSecure
    , connectionIsSecure
    ) where

import Control.Applicative
import Control.Concurrent.MVar

import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLS

import System.Certificate.X509 (getSystemCertificateStore)

import Network.Socks5
import qualified Network as N

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Random.AESCtr as RNG

import System.IO
import qualified Data.Map as M

import Network.Connection.Types

type Manager = MVar (M.Map TLS.SessionID TLS.SessionData)
data ConnectionSessionManager = ConnectionSessionManager Manager

instance TLS.SessionManager ConnectionSessionManager where
    sessionResume (ConnectionSessionManager mvar) sessionID =
        withMVar mvar (return . M.lookup sessionID)
    sessionEstablish (ConnectionSessionManager mvar) sessionID sessionData =
        modifyMVar_ mvar (return . M.insert sessionID sessionData)
    sessionInvalidate (ConnectionSessionManager mvar) sessionID =
        modifyMVar_ mvar (return . M.delete sessionID)

-- | Initialize the library with shared parameters between connection.
initConnectionContext :: IO ConnectionContext
initConnectionContext = ConnectionContext <$> getSystemCertificateStore

makeTLSParams :: ConnectionContext -> TLSSettings -> TLS.Params
makeTLSParams cg ts@(TLSSettingsSimple {}) =
    TLS.defaultParamsClient
        { TLS.pConnectVersion    = TLS.TLS11
        , TLS.pAllowedVersions   = [TLS.TLS10,TLS.TLS11,TLS.TLS12]
        , TLS.pCiphers           = TLS.ciphersuite_all
        , TLS.pCertificates      = []
        , TLS.onCertificatesRecv = if settingDisableCertificateValidation ts
                                       then const $ return TLS.CertificateUsageAccept
                                       else TLS.certificateVerifyChain (globalCertificateStore cg)
        }
makeTLSParams _ (TLSSettings p) = p

withBackend :: (ConnectionBackend -> IO a) -> Connection -> IO a
withBackend f conn = modifyMVar (connectionBackend conn) (\b -> f b >>= \a -> return (b,a))

withBuffer :: (ByteString -> IO (ByteString, b)) -> Connection -> IO b
withBuffer f conn = modifyMVar (connectionBuffer conn) f

connectionNew :: ConnectionParams -> ConnectionBackend -> IO Connection
connectionNew p backend = Connection <$> newMVar backend <*> newMVar B.empty <*> pure (connectionHostname p, connectionPort p)

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
-- The size argument is just the maximum that could be returned to the user,
-- however the call will returns as soon as there's data, even if there's less
-- data than expected.
connectionGet :: Connection -> Int -> IO ByteString
connectionGet conn size = connectionGetChunk' conn $ B.splitAt size

-- | Get the next block of data from the connection.
connectionGetChunk :: Connection -> IO ByteString
connectionGetChunk conn = connectionGetChunk' conn $ \s -> (s, B.empty)

-- | Like 'connectionGetChunk', but return the unused portion to the buffer,
-- where it will be the next chunk read.
connectionGetChunk' :: Connection -> (ByteString -> (a, ByteString)) -> IO a
connectionGetChunk' conn f = withBuffer getData conn
  where getData buf
          | B.null buf = do
              chunk <- withBackend getMoreData conn
              return $ swap $ f chunk
          | otherwise =
              return $ swap $ f buf

        getMoreData (ConnectionTLS tlsctx) = TLS.recvData tlsctx
        getMoreData (ConnectionStream h)   = B.hGetSome h (16 * 1024)

        swap (a, b) = (b, a)

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
                                       return (ConnectionTLS ctx, B.empty)
            (ConnectionTLS _)    -> return (backend, b)

-- | Returns if the connection is establish securely or not.
connectionIsSecure :: Connection -> IO Bool
connectionIsSecure conn = withBackend isSecure conn
    where isSecure (ConnectionStream _) = return False
          isSecure (ConnectionTLS _)    = return True

tlsEstablish :: Handle -> TLS.TLSParams -> IO TLS.Context
tlsEstablish handle tlsParams = do
    rng <- RNG.makeSystem
    ctx <- TLS.contextNewOnHandle handle tlsParams rng
    TLS.handshake ctx
    return ctx
