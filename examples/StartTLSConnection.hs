{-# LANGUAGE OverloadedStrings #-}
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import Network.Connection
import Data.Default

main = do
    ctx <- initConnectionContext
    con <- connectTo ctx $ ConnectionParams
                              { connectionHostname  = "www.example.com"
                              , connectionPort      = 4567
                              , connectionUseSecure = Nothing
                              , connectionUseSocks  = Nothing
                              }
    -- talk to the other side, says hello and starttls 
    connectionPut con "HELLO\n"
    connectionPut con "STARTTLS\n"

    -- switch to TLS
    connectionSetSecure ctx con def

    -- the connection is now on using TLS, we can send secret for examplek
    connectionPut con "PASSWORD 123\n"
    connectionClose con
