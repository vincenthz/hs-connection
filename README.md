haskell Connection library
==========================

Simple network library for all your connection need.

Features:

- Really simple to use
- SSL/TLS
- SOCKS

Usage
-----

Connect to www.example.com on port 4567 (without socks or tls), then send a
byte, receive a single byte, print it, and close the connection:

    import qualified Data.ByteString as B
    import Network.Connection
    import Data.Default

    main = do
        ctx <- initConnectionContext
        con <- connectTo ctx $ ConnectionParams
                                  { connectionHostname   = "www.example.com"
                                  , connectionPort       = 4567
                                  , connectionUseAddress = Nothing
                                  , connectionUseSecure  = Nothing
                                  , connectionUseSocks   = Nothing
                                  }
        connectionPut con (B.singleton 0xa)
        r <- connectionGet con 1
        putStrLn $ show r
        connectionClose con

Using a socks proxy is easy, we just need replacing the connectionSocks
parameter, for example connecting to the same host, but using a socks
proxy at localhost:1080:

    con <- connectTo ctx $ ConnectionParams
                           { connectionHostname   = "www.example.com"
                           , connectionPort       = 4567
                           , connectionUseAddress = Nothing
                           , connectionUseSecure  = Nothing
                           , connectionUseSocks   = Just $ SockSettingsSimple "localhost" 1080
                           }

Connecting to a SSL style socket is equally easy, and need to set the UseSecure fields in ConnectionParams:

    con <- connectTo ctx $ ConnectionParams
                           { connectionHostname   = "www.example.com"
                           , connectionPort       = 4567
                           , connectionUseAddress = Nothing
                           , connectionUseSecure  = Just def
                           , connectionUseSocks   = Nothing
                           }

And finally, you can start TLS in the middle of an insecure connection. This is great for
protocol using STARTTLS (e.g. IMAP, SMTP):

    {-# LANGUAGE OverloadedStrings #-}
    import qualified Data.ByteString as B
    import Data.ByteString.Char8 ()
    import Network.Connection
    import Data.Default

    main = do
        ctx <- initConnectionContext
        con <- connectTo ctx $ ConnectionParams
                                  { connectionHostname   = "www.example.com"
                                  , connectionPort       = 4567
                                  , connectionUseAddress = Nothing
                                  , connectionUseSecure  = Nothing
                                  , connectionUseSocks   = Nothing
                                  }
        -- talk to the other side with no TLS: says hello and starttls
        connectionPut con "HELLO\n"
        connectionPut con "STARTTLS\n"

        -- switch to TLS
        connectionSetSecure ctx con def

        -- the connection is from now on using TLS, we can send secret for example
        connectionPut con "PASSWORD 123\n"
        connectionClose con
