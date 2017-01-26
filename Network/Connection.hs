{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
    , ProxySettings(..)
    , SockSettings

    -- * Exceptions
    , LineTooLong(..)
    , HostNotResolved(..)
    , HostCannotConnect(..)

    -- * Library initialization
    , initConnectionContext
    , ConnectionContext

    -- * Connection operation
    , connectFromHandle
    , connectFromSocket
    , connectTo
    , connectionClose

    -- * Sending and receiving data
    , connectionGet
    , connectionGetExact
    , connectionGetChunk
    , connectionGetChunk'
    , connectionGetLine
    , connectionWaitForInput
    , connectionPut

    -- * TLS related operation
    , connectionSetSecure
    , connectionIsSecure
    ) where

import Control.Applicative
import Control.Concurrent.MVar
import Control.Monad (join)
import qualified Control.Exception as E
import qualified System.IO.Error as E (mkIOError, eofErrorType)

import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLS

import System.X509 (getSystemCertificateStore)

import Network.Socks5
import qualified Network as N
import Network.Socket
import Network.BSD (getProtocolNumber)
import qualified Network.Socket as N (close)
import qualified Network.Socket.ByteString as N

import Data.Default.Class
import Data.Data
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L

import System.Environment
import System.Timeout
import System.IO
import qualified Data.Map as M

import Network.Connection.Types

type Manager = MVar (M.Map TLS.SessionID TLS.SessionData)

-- | This is the exception raised if we reached the user specified limit for
-- the line in ConnectionGetLine.
data LineTooLong = LineTooLong deriving (Show,Typeable)

-- | Exception raised when there's no resolution for a specific host
data HostNotResolved = HostNotResolved String deriving (Show,Typeable)

-- | Exception raised when the connect failed
data HostCannotConnect = HostCannotConnect String [E.IOException] deriving (Show,Typeable)

instance E.Exception LineTooLong
instance E.Exception HostNotResolved
instance E.Exception HostCannotConnect

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

-- | Create a final TLS 'ClientParams' according to the destination and the
-- TLSSettings.
makeTLSParams :: ConnectionContext -> ConnectionID -> TLSSettings -> TLS.ClientParams
makeTLSParams cg cid ts@(TLSSettingsSimple {}) =
    (TLS.defaultParamsClient (fst cid) portString)
        { TLS.clientSupported = def { TLS.supportedCiphers = TLS.ciphersuite_all }
        , TLS.clientShared    = def
            { TLS.sharedCAStore         = globalCertificateStore cg
            , TLS.sharedValidationCache = validationCache
            -- , TLS.sharedSessionManager  = connectionSessionManager
            }
        }
  where validationCache
            | settingDisableCertificateValidation ts =
                TLS.ValidationCache (\_ _ _ -> return TLS.ValidationCachePass)
                                    (\_ _ _ -> return ())
            | otherwise = def
        portString = BC.pack $ show $ snd cid
makeTLSParams _ cid (TLSSettings p) =
    p { TLS.clientServerIdentification = (fst cid, portString) }
 where portString = BC.pack $ show $ snd cid

withBackend :: (ConnectionBackend -> IO a) -> Connection -> IO a
withBackend f conn = readMVar (connectionBackend conn) >>= f

connectionNew :: ConnectionID -> ConnectionBackend -> IO Connection
connectionNew cid backend =
    Connection <$> newMVar backend
               <*> newMVar (Just B.empty)
               <*> pure cid

-- | Use an already established handle to create a connection object.
--
-- if the TLS Settings is set, it will do the handshake with the server.
-- The SOCKS settings have no impact here, as the handle is already established
connectFromHandle :: ConnectionContext
                  -> Handle
                  -> ConnectionParams
                  -> IO Connection
connectFromHandle cg h p = withSecurity (connectionUseSecure p)
    where withSecurity Nothing            = connectionNew cid $ ConnectionStream h
          withSecurity (Just tlsSettings) = tlsEstablish h (makeTLSParams cg cid tlsSettings) >>= connectionNew cid . ConnectionTLS
          cid = (connectionHostname p, connectionPort p)

-- | Use an already established handle to create a connection object.
--
-- if the TLS Settings is set, it will do the handshake with the server.
-- The SOCKS settings have no impact here, as the handle is already established
connectFromSocket :: ConnectionContext
                  -> Socket
                  -> ConnectionParams
                  -> IO Connection
connectFromSocket cg sock p = withSecurity (connectionUseSecure p)
    where withSecurity Nothing            = connectionNew cid $ ConnectionSocket sock
          withSecurity (Just tlsSettings) = tlsEstablish sock (makeTLSParams cg cid tlsSettings) >>= connectionNew cid . ConnectionTLS
          cid = (connectionHostname p, connectionPort p)

-- | connect to a destination using the parameter
connectTo :: ConnectionContext -- ^ The global context of this connection.
          -> ConnectionParams  -- ^ The parameters for this connection (where to connect, and such).
          -> IO Connection     -- ^ The new established connection on success.
connectTo cg cParams = do
    conFct <- getConFct (connectionUseSocks cParams)
    let doConnect = conFct (connectionHostname cParams) (N.PortNumber $ connectionPort cParams)
    E.bracketOnError doConnect N.close $ \h->
        connectFromSocket cg h cParams
  where
        getConFct Nothing                            = return resolve'
        getConFct (Just (OtherProxy h p))            = return $ \_ _ -> resolve' h (N.PortNumber p)
        getConFct (Just (SockSettingsSimple h p))    = return $ socksConnectTo' h (N.PortNumber p)
        getConFct (Just (SockSettingsEnvironment v)) = do
            -- if we can't get the environment variable or that the variable cannot be parsed
            -- we connect directly.
            let name = maybe "SOCKS_SERVER" id v
            evar <- E.try (getEnv name)
            case evar of
                Left (_ :: E.IOException) -> return resolve'
                Right var                 ->
                    case parseSocks var of
                        Nothing             -> return resolve'
                        Just (sHost, sPort) -> return $ socksConnectTo' sHost (N.PortNumber $ fromIntegral (sPort :: Int))

        -- Try to parse "host:port" or "host"
        parseSocks s =
            case break (== ':') s of
                (sHost, "")        -> Just (sHost, 1080)
                (sHost, ':':portS) ->
                    case reads portS of
                        [(sPort,"")] -> Just (sHost, sPort)
                        _            -> Nothing
                _                  -> Nothing

        resolve' host portid = do
            let serv = case portid of
                            N.Service serv -> serv
                            N.PortNumber n -> show n
                            _              -> error "cannot resolve service" 
            proto <- getProtocolNumber "tcp"
            let hints = defaultHints { addrFlags = [AI_ADDRCONFIG]
                                     , addrProtocol = proto
                                     , addrSocketType = Stream }
            addrs <- getAddrInfo (Just hints) (Just host) (Just serv)
            firstSuccessful $ map tryToConnect addrs
          where
            tryToConnect addr =
                E.bracketOnError
                    (socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr))
                    (N.close)
                    (\sock -> connect sock (addrAddress addr) >> return sock)
            firstSuccessful = go []
              where
                go :: [E.IOException] -> [IO a] -> IO a
                go []      [] = E.throwIO $ HostNotResolved host
                go l@(_:_) [] = E.throwIO $ HostCannotConnect host l
                go acc     (act:followingActs) = do
                    er <- E.try act
                    case er of
                        Left err -> go (err:acc) followingActs
                        Right r  -> return r

-- | Put a block of data in the connection.
connectionPut :: Connection -> ByteString -> IO ()
connectionPut connection content = withBackend doWrite connection
    where doWrite (ConnectionStream h) = B.hPut h content >> hFlush h
          doWrite (ConnectionSocket s) = N.sendAll s content
          doWrite (ConnectionTLS ctx)  = TLS.sendData ctx $ L.fromChunks [content]

-- | Get exact count of bytes from a connection.
--
-- The size argument is the exact amount that must be returned to the user.
-- The call will wait until all data is available.  Hence, it behaves like
-- 'B.hGet'.
--
-- On end of input, 'connectionGetExact' will throw an 'E.isEOFError'
-- exception.
connectionGetExact :: Connection -> Int -> IO ByteString
connectionGetExact conn x = loop B.empty 0
  where loop bs y
          | y == x = return bs
          | otherwise = do
            next <- connectionGet conn (x - y)
            loop (B.append bs next) (y + (B.length next))

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

-- | Wait for input to become available on a connection.
--
-- As with 'hWaitForInput', the timeout value is given in milliseconds.  If the
-- timeout value is less than zero, then 'connectionWaitForInput' waits
-- indefinitely.
--
-- Unlike 'hWaitForInput', this function does not do any decoding, so it
-- returns true when there is /any/ available input, not just full characters.
connectionWaitForInput :: Connection -> Int -> IO Bool
connectionWaitForInput conn timeout_ms = maybe False (const True) <$> timeout timeout_ns tryGetChunk
  where tryGetChunk = connectionGetChunkBase "connectionWaitForInput" conn $ \buf -> ((), buf)
        timeout_ns  = timeout_ms * 1000

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
    getMoreData (ConnectionSocket sock) = N.recv sock 1500
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
          else case B.break (== 10) s of
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
          backendClose (ConnectionSocket sock) = N.close sock
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
            (ConnectionStream h) -> do ctx <- tlsEstablish h (makeTLSParams cg (connectionID connection) params)
                                       return (ConnectionTLS ctx, Just B.empty)
            (ConnectionSocket s) -> do ctx <- tlsEstablish s (makeTLSParams cg (connectionID connection) params)
                                       return (ConnectionTLS ctx, Just B.empty)
            (ConnectionTLS _)    -> return (backend, b)

-- | Returns if the connection is establish securely or not.
connectionIsSecure :: Connection -> IO Bool
connectionIsSecure conn = withBackend isSecure conn
    where isSecure (ConnectionStream _) = return False
          isSecure (ConnectionSocket _) = return False
          isSecure (ConnectionTLS _)    = return True

tlsEstablish :: TLS.HasBackend backend => backend -> TLS.ClientParams -> IO TLS.Context
tlsEstablish handle tlsParams = do
    ctx <- TLS.contextNew handle tlsParams
    TLS.handshake ctx
    return ctx
