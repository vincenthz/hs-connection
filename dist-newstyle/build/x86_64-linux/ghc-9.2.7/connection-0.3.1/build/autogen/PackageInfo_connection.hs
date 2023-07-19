{-# LANGUAGE NoRebindableSyntax #-}
{-# OPTIONS_GHC -fno-warn-missing-import-lists #-}
{-# OPTIONS_GHC -w #-}
module PackageInfo_connection (
    name,
    version,
    synopsis,
    copyright,
    homepage,
  ) where

import Data.Version (Version(..))
import Prelude

name :: String
name = "connection"
version :: Version
version = Version [0,3,1] []

synopsis :: String
synopsis = "Simple and easy network connections API"
copyright :: String
copyright = "Vincent Hanquez <vincent@snarc.org>"
homepage :: String
homepage = "https://github.com/vincenthz/hs-connection"
