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
    , initConnection
    , ConnectionGlobal

    -- * Connection operation
    , connectFromHandle
    , connectTo
    , connectionClose

    -- * Sending and receiving data
    , connectionGet
    , connectionGetChunk
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
initConnection :: IO ConnectionGlobal
initConnection = ConnectionGlobal <$> getSystemCertificateStore

makeTLSParams :: ConnectionGlobal -> TLSSettings -> TLS.Params
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

withBackendModify :: (ConnectionBackend -> IO ConnectionBackend) -> Connection -> IO ()
withBackendModify f conn = modifyMVar_ (connectionBackend conn) f

connectionNew :: ConnectionParams -> ConnectionBackend -> IO Connection
connectionNew p backend = Connection <$> newMVar backend <*> newMVar B.empty <*> pure (connectionHostname p, connectionPort p)

-- | Use an already established handle to create a connection object.
--
-- if the TLS Settings is set, it will do the handshake with the server.
-- The SOCKS settings have no impact here, as the handle is already established
connectFromHandle :: ConnectionGlobal
                  -> Handle
                  -> ConnectionParams
                  -> IO Connection
connectFromHandle cg h p = withSecurity (connectionUseSecure p)
    where withSecurity Nothing            = connectionNew p $ ConnectionStream h
          withSecurity (Just tlsSettings) = tlsEstablish h (makeTLSParams cg tlsSettings) >>= connectionNew p . ConnectionTLS

-- | connect to a destination using the parameter
connectTo :: ConnectionGlobal -- ^ The global context of this connection.
          -> ConnectionParams -- ^ The parameters for this connection (where to connect, and such).
          -> IO Connection    -- ^ The new established connection on success.
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
connectionGet con size = withBuffer getData con
    where getData buf
                | B.null buf           = do chunk <- withBackend getMoreData con
                                            let (ret, remain) = B.splitAt size chunk
                                            return (remain, ret)
                | B.length buf >= size = let (ret, remain) = B.splitAt size buf
                                          in return (remain, ret)
                | otherwise            = return (B.empty, buf)
          getMoreData (ConnectionTLS tlsctx) = TLS.recvData tlsctx
          getMoreData (ConnectionStream h)   = hWaitForInput h (-1) >> B.hGetNonBlocking h (16 * 1024)

-- | Get the next block of data from the connection.
connectionGetChunk :: Connection -> IO ByteString
connectionGetChunk con = withBuffer getData con
    where getData buf
                | B.null buf = withBackend getMoreData con >>= \chunk -> return (B.empty, chunk)
                | otherwise  = return (B.empty, buf)
          getMoreData (ConnectionTLS tlsctx) = TLS.recvData tlsctx
          getMoreData (ConnectionStream h)   = hWaitForInput h (-1) >> B.hGetNonBlocking h (16 * 1024)

-- | Close a connection.
connectionClose :: Connection -> IO ()
connectionClose = withBackend backendClose
    where backendClose (ConnectionTLS ctx)  = TLS.bye ctx >> TLS.contextClose ctx
          backendClose (ConnectionStream h) = hClose h

-- | Activate secure layer using the parameters specified.
-- 
-- This is typically used to negociate a TLS channel on an already
-- establish channel, e.g. supporting a STARTTLS command.
-- 
-- If the connection is already using TLS, nothing else happens.
connectionSetSecure :: ConnectionGlobal
                    -> Connection
                    -> TLSSettings
                    -> IO ()
connectionSetSecure cg connection params = withBackendModify switchToTLS connection
    where switchToTLS (ConnectionStream h) = ConnectionTLS <$> tlsEstablish h (makeTLSParams cg params)
          switchToTLS s@(ConnectionTLS _)  = return s

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
