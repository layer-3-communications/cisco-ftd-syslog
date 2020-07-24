{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language NamedFieldPuns #-}
{-# language MagicHash #-}
{-# language LambdaCase #-}
{-# language DeriveAnyClass #-}

module Cisco.Ftd.Syslog
  ( Message(..)
  , Attribute(..)
  , decode
  ) where

import Control.Exception (Exception)
import Data.Builder.ST (Builder)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Bytes.Parser (Parser,Result(Success,Failure),Slice(Slice))
import Data.Chunks (Chunks)
import Data.Word (Word16,Word64)
import GHC.Exts (Ptr(Ptr))
import Net.Types (IPv4)

import qualified Net.IPv4 as IPv4
import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

-- More fields may be added later.
newtype Message = Message
  { attributes :: (Chunks Attribute)
  }

data Attribute
  = SourceIp !IPv4
  | DestinationIp !IPv4
  | SourcePort !Word16
  | DestinationPort !Word16
  | Protocol {-# UNPACK #-} !Bytes
  | IngressInterface {-# UNPACK #-} !Bytes
  | EgressInterface {-# UNPACK #-} !Bytes
  | IngressZone {-# UNPACK #-} !Bytes
  | EgressZone {-# UNPACK #-} !Bytes
  | AccessControlRuleAction {-# UNPACK #-} !Bytes
  | ApplicationProtocol {-# UNPACK #-} !Bytes
  | HttpResponse {-# UNPACK #-} !Bytes
  | ReferencedHost {-# UNPACK #-} !Bytes
  deriving stock (Eq,Show)

decode :: Bytes -> Maybe Message
decode b = Parser.parseBytesMaybe parser b

parser :: Parser () s Message
parser = do
  skipSyslogPriority
  skipInitialDate
  Latin.skipChar1 () ' '
  Parser.cstring () (Ptr "%FTD-1-430003: "#)
  r <- parserKeyValue =<< Parser.effect Builder.new
  pure Message{attributes=r}
  
parserKeyValue :: Builder s Attribute -> Parser () s (Chunks Attribute)
parserKeyValue !b0 = do
  key <- Latin.takeTrailedBy () ':'
  Latin.char () ' '
  b1 <- case Bytes.length key of
    23 | Bytes.equalsCString (Ptr "AccessControlRuleAction"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = AccessControlRuleAction txt
           Parser.effect (Builder.push x b0)
    19 | Bytes.equalsCString (Ptr "ApplicationProtocol"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = ApplicationProtocol txt
           Parser.effect (Builder.push x b0)
    7 | Bytes.equalsCString (Ptr "SrcPort"#) key -> do
          !addr <- Latin.decWord16 ()
          let !x = SourcePort addr
          Parser.effect (Builder.push x b0)
      | Bytes.equalsCString (Ptr "DstPort"#) key -> do
          !addr <- Latin.decWord16 ()
          let !x = DestinationPort addr
          Parser.effect (Builder.push x b0)
      | Bytes.equalsCString (Ptr "Protocol"#) key -> do
          txt <- Parser.takeWhile (/=0x2C)
          let !x = Protocol txt
          Parser.effect (Builder.push x b0)
    5 | Bytes.equalsCString (Ptr "SrcIP"#) key -> do
          !addr <- IPv4.parserUtf8Bytes ()
          let !x = SourceIp addr
          Parser.effect (Builder.push x b0)
      | Bytes.equalsCString (Ptr "DstIP"#) key -> do
          !addr <- IPv4.parserUtf8Bytes ()
          let !x = DestinationIp addr
          Parser.effect (Builder.push x b0)
    _ -> do
      Parser.skipWhile (/=0x2C)
      pure b0
  Parser.isEndOfInput >>= \case
    True -> Parser.effect (Builder.freeze b1)
    False -> do
      Latin.char2 () ',' ' '
      parserKeyValue b1 

skipSyslogPriority :: Parser () s ()
skipSyslogPriority = Latin.trySatisfy (== '<') >>= \case
  True -> do
    Latin.skipDigits1 ()
    Latin.char () '>'
  False -> pure ()

-- Dates look like: YYYY-MM-DDTHH:MM:SSZ
skipInitialDate :: Parser () s ()
skipInitialDate = do
  Latin.skipDigits1 ()
  Latin.char () '-'
  Latin.skipDigits1 ()
  Latin.char () '-'
  Latin.skipDigits1 ()
  Latin.char () 'T'
  Latin.skipDigits1 ()
  Latin.char () ':'
  Latin.skipDigits1 ()
  Latin.char () ':'
  Latin.skipDigits1 ()
  Latin.char () 'Z'
