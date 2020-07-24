{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language MultiWayIf #-}
{-# language NamedFieldPuns #-}
{-# language TypeApplications #-}

import Cisco.Ftd.Syslog

import Control.Exception (throwIO)
import Data.Primitive (ByteArray)
import Data.Word (Word8)
import Data.Char (ord)
import Data.Bytes.Types (Bytes(Bytes))

import qualified Data.Primitive as PM
import qualified Data.Bytes as Bytes
import qualified GHC.Exts as Exts
import qualified Net.IPv4 as IPv4
import qualified Sample as S

main :: IO ()
main = do
  putStrLn "Start"
  putStrLn "test1"
  test1
  putStrLn "End"

test1 :: IO ()
test1 = case decode S.sample1 of
  Nothing -> fail "could not decode test1"
  Just (Message attrs)
    | notElem (DestinationPort 80) attrs -> fail "bad destination port"
    | otherwise -> pure ()

bytes :: String -> Bytes
bytes s = let b = pack s in Bytes b 0 (PM.sizeofByteArray b)

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)
