-- |
-- Module      : Network.Connection.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : portable
--
-- connection types
--
module Network.Connection.Types
    where

import Control.Concurrent.MVar (MVar)

import Data.Default
import Data.CertificateStore
import Data.ByteString (ByteString)

import Network.BSD (HostName)
import Network.Socket (PortNumber)
import qualified Network.TLS as TLS

import System.IO (Handle)

data ConnectionBackend = ConnectionStream Handle
                       | ConnectionTLS TLS.Context

-- | Connection Parameters to establish a Connection.
--
-- The strict minimum is an hostname and the port.
--
-- If you need to establish a TLS connection, you should make sure
-- connectionUseSecure is correctly set.
--
-- If you need to connect through a SOCKS, you should make sure
-- connectionUseSocks is correctly set.
data ConnectionParams = ConnectionParams
    { connectionHostname   :: HostName           -- ^ host name to connect to.
    , connectionPort       :: PortNumber         -- ^ port number to connect to.
    , connectionUseSecure  :: Maybe TLSSettings  -- ^ optional TLS parameters.
    , connectionUseSocks   :: Maybe SockSettings -- ^ optional Socks configuration.
    }

data SockSettings = SockSettingsSimple HostName PortNumber

-- | TLS Settings that can be either expressed as simple settings,
-- or as full blown TLS.Params settings.
--
-- Unless you need access to parameters that are not accessible through the
-- simple settings, you should use TLSSettingsSimple.
data TLSSettings
    = TLSSettingsSimple
             { settingDisableCertificateValidation :: Bool
             , settingDisableSession               :: Bool
             , settingUseServerName                :: Bool
             }
    | TLSSettings TLS.Params
    deriving (Show)

instance Default TLSSettings where
    def = TLSSettingsSimple False False False

-- | This opaque type represent a connection to a destination.
data Connection = Connection
    { connectionBackend :: MVar ConnectionBackend
    , connectionBuffer  :: MVar ByteString
    , connectionID      :: (HostName, PortNumber)  -- ^ return a simple tuple of the port and hostname that we're connected to.
    }

-- | Shared values (certificate store, sessions, ..) between connections
--
-- At the moment, this is only strictly needed to shared sessions and certificates
-- when using a TLS enabled connection.
data ConnectionContext = ConnectionContext
    { globalCertificateStore :: !CertificateStore
    }
