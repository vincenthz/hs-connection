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

    main = do
        ctx <- initConnectionContext
        con <- connectTo ctx $ ConnectionParams
                                  { connectionHostname  = "www.example.com"
                                  , connectionPort      = fromIntegral 4567
                                  , connectionUseSecure = Nothing
                                  , connectionSocks     = Nothing
                                  }
        connectionPut con (B.singleton 0xa)
        r <- connectionGet con 1
        putStrLn $ show r
        connectionClose con

Using a socks proxy is easy, we just need replacing the connectionSocks
parameter, for example connecting to the same host, but using a socks
proxy at localhost:1080:

    connectionSocks =
    con <- connectTo $ ConnectionParams
                           { connectionHostname  = "www.example.com"
                           , connectionPort      = fromIntegral 4567
                           , connectionUseSecure = Nothing
                           , connectionSocks     = Just $ SockSettingsSimple "localhost" (fromIntegral 1080)
                           }
