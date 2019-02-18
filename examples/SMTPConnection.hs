{-# LANGUAGE OverloadedStrings #-}
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import Network.Connection
import Data.Default

readHeader con = do
    l <- connectionGetLine 1024 con
    putStrLn $ show l
    if B.isPrefixOf "250 " l
        then return ()
        else readHeader con

main = do
    ctx <- initConnectionContext
    con <- connectTo ctx $ ConnectionParams
                            { connectionHostname   = "my.smtp.server"
                            , connectionPort       = 25
                            , connectionUseAddress = Nothing
                            , connectionUseSecure  = Nothing
                            , connectionUseSocks   = Nothing
                            }

    -- | read the server banner
    connectionGetLine 1024 con >>= putStrLn . show
    -- | say ehlo to the smtp server
    connectionPut con "EHLO\n"
    -- | wait for a reply and print
    readHeader con
    -- | Tell the server to start a TLS context.
    connectionPut con "STARTTLS\n"
    -- | wait for a reply and print
    connectionGetLine 1024 con >>= putStrLn . show

    -- | negociate the TLS context
    connectionSetSecure ctx con def

    ------- connection is secure now
    connectionPut con "QUIT\n"
    connectionClose con
