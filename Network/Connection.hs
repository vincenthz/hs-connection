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
    , TLSConf
    , TLSSetting(..)

    -- * Library initialization
    , initConnection
    , ConnectionGlobal

    -- * TLS configuration creation
    , tlsConfSimple
    , tlsConf

    -- * Connection methods
    , connectFromHandle
    , connectTo
    , connectionGet
    , connectionPut
    , connectionClose
    , connectionSetSecure
    , connectionIsSecure
    ) where

import Control.Applicative
import Control.Concurrent.MVar

import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLS

import Data.CertificateStore
import System.Certificate.X509 (getSystemCertificateStore)

import Network.BSD (HostName)
import Network.Socket (PortNumber)
import Network.Socks5
import qualified Network as N

import Data.Default
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Random.AESCtr as RNG

import System.IO
import qualified Data.Map as M

data ConnectionBackend = ConnectionStream Handle
                       | ConnectionTLS TLS.Context

data ConnectionParams = ConnectionParams
    { connectionHostname   :: HostName        -- ^ host name to connect to.
    , connectionPort       :: PortNumber       -- ^ port number to connect to.
    , connectionSocks      :: Maybe SocksConf  -- ^ optional Socks configuration.
    , connectionUseSecure  :: Maybe TLSConf   -- ^ optional TLS parameters.
    }

data TLSConf = TLSConf TLS.Params

type Manager = MVar (M.Map TLS.SessionID TLS.SessionData)
data ConnectionSessionManager = ConnectionSessionManager Manager

instance TLS.SessionManager ConnectionSessionManager where
    sessionResume (ConnectionSessionManager mvar) sessionID =
        withMVar mvar (return . M.lookup sessionID)
    sessionEstablish (ConnectionSessionManager mvar) sessionID sessionData =
        modifyMVar_ mvar (return . M.insert sessionID sessionData)
    sessionInvalidate (ConnectionSessionManager mvar) sessionID =
        modifyMVar_ mvar (return . M.delete sessionID)

-- | This opaque type represent a connection to a destination.
data Connection = Connection
    { connectionBackend :: MVar ConnectionBackend
    , connectionID      :: (HostName, PortNumber)  -- ^ return a simple tuple of the port and hostname that we're connected to.
    }

-- | Shared values (certificate store, sessions, ..) between connections
data ConnectionGlobal = ConnectionGlobal
    { globalCertificateStore :: !CertificateStore
    }

-- | Simple setting tweak related to SSL/TLS
data TLSSetting = TLSSetting
    { settingDisableCertificateValidation :: Bool
    , settingDisableSession               :: Bool
    , settingUseServerName                :: Bool
    }

instance Default TLSSetting where
    def = TLSSetting False False False

-- | Initialize the library with shared parameters between connection.
-- only necessary for TLS
initConnection :: IO ConnectionGlobal
initConnection = ConnectionGlobal <$> getSystemCertificateStore

-- | Simple parameters with all correct default values set for secure connection.
tlsConfSimple :: ConnectionGlobal -> TLSSetting -> TLSConf
tlsConfSimple cg ts = TLSConf $ TLS.defaultParamsClient
        { TLS.pConnectVersion    = TLS.TLS11
        , TLS.pAllowedVersions   = [TLS.TLS10,TLS.TLS11,TLS.TLS12]
        , TLS.pCiphers           = TLS.ciphersuite_all
        , TLS.pCertificates      = []
        , TLS.onCertificatesRecv = if settingDisableCertificateValidation ts
                                       then const $ return TLS.CertificateUsageAccept
                                       else TLS.certificateVerifyChain (globalCertificateStore cg)
        }

-- | allow to set parameters
tlsConf :: TLS.TLSParams -> TLSConf
tlsConf = TLSConf

withBackend :: (ConnectionBackend -> IO a) -> Connection -> IO a
withBackend f conn = modifyMVar (connectionBackend conn) (\b -> f b >>= \a -> return (b,a))

withBuffer :: (ByteString -> IO (ByteString, b)) -> Connection -> IO b
withBuffer f conn = modifyMVar (connectionBuffer conn) f

withBackendModify :: (ConnectionBackend -> IO ConnectionBackend) -> Connection -> IO ()
withBackendModify f conn = modifyMVar_ (connectionBackend conn) f

connectionNew :: ConnectionParams -> ConnectionBackend -> IO Connection
connectionNew p backend = Connection <$> newMVar backend <*> pure (connectionHostname p, connectionPort p)

connectFromHandle :: Handle -> ConnectionParams -> IO Connection
connectFromHandle h p = withSecurity (connectionUseSecure p)
    where withSecurity Nothing                    = connectionNew p $ ConnectionStream h
          withSecurity (Just (TLSConf tlsParams)) = tlsEstablish h tlsParams >>= connectionNew p . ConnectionTLS

-- | connect to a destination using the parameters specified.
connectTo :: ConnectionParams -> IO Connection
connectTo cParams = do
        h <- conFct (connectionHostname cParams) (N.PortNumber $ connectionPort cParams)        
        connectFromHandle h cParams
    where
        conFct = case connectionSocks cParams of
                      Nothing   -> N.connectTo
                      Just conf -> socksConnectTo (socksHost conf) (N.PortNumber $ socksPort conf)

-- | Put a block of data in the connection.
connectionPut :: Connection -> ByteString -> IO ()
connectionPut connection content = withBackend doWrite connection
    where doWrite (ConnectionStream h) = B.hPut h content >> hFlush h
          doWrite (ConnectionTLS ctx)  = TLS.sendData ctx $ L.fromChunks [content]

-- | Get the next block of data from the connection.
connectionGet :: Connection -> IO ByteString
connectionGet = withBackend getMoreData
    where getMoreData (ConnectionTLS tlsctx) = TLS.recvData tlsctx
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
connectionSetSecure :: Connection -> TLS.TLSParams -> IO ()
connectionSetSecure connection params = do
        withBackendModify switchToTLS connection
    where switchToTLS (ConnectionStream h) = ConnectionTLS <$> tlsEstablish h params
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
