import qualified Data.ByteString as B
import Network.Connection

main = do
    ctx <- initConnectionContext
    con <- connectTo ctx $ ConnectionParams
                              { connectionHostname  = "www.example.com"
                              , connectionPort      = 4567
                              , connectionUseSecure = Nothing
                              , connectionUseSocks  = Nothing
                              }
    connectionPut con (B.singleton 0xa)
    r <- connectionGet con 1024
    putStrLn $ show r
    connectionClose con
