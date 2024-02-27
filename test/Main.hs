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
  putStrLn "test3"
  test3
  putStrLn "test4"
  test4
  putStrLn "test5"
  test5
  putStrLn "test6"
  test6
  putStrLn "End"

test1 :: IO ()
test1 = case decode S.sample1 of
  Nothing -> fail "could not decode test1"
  Just (Message _ _ _ attrs)
    | notElem (DestinationPort 80) attrs -> fail "bad destination port"
    | notElem (InitiatorPackets 11) attrs -> fail "bad initiator packets"
    | notElem (ResponderPackets 6) attrs -> fail "bad responder packets"
    | notElem (InitiatorBytes 7023) attrs -> fail "bad initiator bytes"
    | notElem (ResponderBytes 875) attrs -> fail "bad responder bytes"
    | notElem (IngressInterface (bytes "Outside")) attrs -> fail "bad ingress interface"
    | notElem (IngressZone (bytes "My-Outside")) attrs -> fail "bad ingress zone"
    | otherwise -> pure ()

test3 :: IO ()
test3 = case decode S.sample3 of
  Nothing -> fail "could not decode test3"
  Just (Message _ _ _ attrs)
    | notElem (DestinationPort 465) attrs -> fail "bad destination port"
    | otherwise -> pure ()

test4 :: IO ()
test4 = case decode S.sample4 of
  Nothing -> fail "could not decode test4"
  Just (Message _ _ _ attrs)
    | notElem (DestinationPort 465) attrs -> fail "bad destination port"
    | otherwise -> pure ()

test5 :: IO ()
test5 = case decode S.sample4 of
  Nothing -> fail "could not decode test5"
  Just _ -> pure ()

test6 :: IO ()
test6 = case decode S.sample4 of
  Nothing -> fail "could not decode test6"
  Just _ -> pure ()

bytes :: String -> Bytes
bytes s = let b = pack s in Bytes b 0 (PM.sizeofByteArray b)

pack :: String -> ByteArray
pack = Exts.fromList . map (fromIntegral @Int @Word8 . ord)
