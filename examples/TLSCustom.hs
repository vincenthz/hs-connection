import qualified Data.ByteString as B
import Network.Connection
import Network.TLS
import Data.Default.Class

-- example for TLSSettingsSimple (disable validation of server certificate)
settingsNoCertValidation =
    TLSSettingsSimple { settingDisableCertificateValidation = True
                      , settingDisableSession = False
                      , settingUseServerName = True
                      }

-- example for TLSSettingsLambda (disable TLS 1.2)
settingsNoTLS12 =
    TLSSettingsLambda $ \cg cid -> overrideParams (defaultClientParams cg cid)
  where
    overrideParams p =
        p { clientSupported = overrideSupported (clientSupported p) }
    overrideSupported s =
        s { supportedVersions = [TLS10, TLS11] -- TLS12 removed
          }

main = do
    ctx <- initConnectionContext
    con <- connectTo ctx $ ConnectionParams
                              { connectionHostname  = "www.example.com"
                              , connectionPort      = 4567
                              , connectionUseSecure = Just settingsNoTLS12
                              , connectionUseSocks  = Nothing
                              }
    connectionPut con (B.singleton 0xa)
    r <- connectionGet con 1024
    putStrLn $ show r
    connectionClose con
