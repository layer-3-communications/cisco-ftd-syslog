{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
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

import qualified Chronos
import qualified Net.IPv4 as IPv4
import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

data Message = Message
  { time :: !Chronos.Datetime
  , attributes :: !(Chunks Attribute)
  }

data Attribute
  = AcPolicy {-# UNPACK #-} !Bytes
  | AccessControlRuleAction {-# UNPACK #-} !Bytes
  | AccessControlRuleName {-# UNPACK #-} !Bytes
  | ApplicationProtocol {-# UNPACK #-} !Bytes
  | ConnectionDuration {-# UNPACK #-} !Word64
  | DestinationIp !IPv4
  | DestinationPort !Word16
  | EgressInterface {-# UNPACK #-} !Bytes
  | EgressZone {-# UNPACK #-} !Bytes
  | HttpReferrer {-# UNPACK #-} !Bytes
  | HttpResponse {-# UNPACK #-} !Word64
  | IngressInterface {-# UNPACK #-} !Bytes
  | IngressZone {-# UNPACK #-} !Bytes
  | InitiatorBytes !Word64
  | InitiatorPackets !Word64
  | NapPolicy {-# UNPACK #-} !Bytes
  | Protocol {-# UNPACK #-} !Bytes
  | ReferencedHost {-# UNPACK #-} !Bytes
  | ResponderBytes !Word64
  | ResponderPackets !Word64
  | SourceIp !IPv4
  | SourcePort !Word16
  | UrlCategory {-# UNPACK #-} !Bytes
  | UserAgent {-# UNPACK #-} !Bytes
  deriving stock (Eq,Show)

decode :: Bytes -> Maybe Message
decode b = Parser.parseBytesMaybe parser b

parser :: Parser () s Message
parser = do
  skipSyslogPriority
  time <- getInitialDate
  Latin.skipChar1 () ' '
  Parser.cstring () (Ptr "%FTD-1-430003: "#)
  r <- parserKeyValue =<< Parser.effect Builder.new
  pure Message{time,attributes=r}
  
parserKeyValue :: Builder s Attribute -> Parser () s (Chunks Attribute)
parserKeyValue !b0 = do
  key <- Latin.takeTrailedBy () ':'
  Latin.char () ' '
  b1 <- case Bytes.length key of
    23 | Bytes.equalsCString (Ptr "AccessControlRuleAction"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = AccessControlRuleAction txt
           Parser.effect (Builder.push x b0)
    21 | Bytes.equalsCString (Ptr "AccessControlRuleName"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = AccessControlRuleName txt
           Parser.effect (Builder.push x b0)
    19 | Bytes.equalsCString (Ptr "ApplicationProtocol"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = ApplicationProtocol txt
           Parser.effect (Builder.push x b0)
    16 | Bytes.equalsCString (Ptr "InitiatorPackets"#) key -> do
           !n <- Latin.decWord64 ()
           let !x = InitiatorPackets n
           Parser.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "ResponderPackets"#) key -> do
           !n <- Latin.decWord64 ()
           let !x = ResponderPackets n
           Parser.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "IngressInterface"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = IngressInterface txt
           Parser.effect (Builder.push x b0)
    15 | Bytes.equalsCString (Ptr "EgressInterface"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = EgressInterface txt
           Parser.effect (Builder.push x b0)
    14 | Bytes.equalsCString (Ptr "InitiatorBytes"#) key -> do
           !n <- Latin.decWord64 ()
           let !x = InitiatorBytes n
           Parser.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "ResponderBytes"#) key -> do
           !n <- Latin.decWord64 ()
           let !x = ResponderBytes n
           Parser.effect (Builder.push x b0)
    11 | Bytes.equalsCString (Ptr "IngressZone"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = IngressZone txt
           Parser.effect (Builder.push x b0)
       | Bytes.equalsCString (Ptr "UrlCategory"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = UrlCategory txt
           Parser.effect (Builder.push x b0)
    10 | Bytes.equalsCString (Ptr "EgressZone"#) key -> do
           txt <- Parser.takeWhile (/=0x2C)
           let !x = EgressZone txt
           Parser.effect (Builder.push x b0)
    9 | Bytes.equalsCString (Ptr "UserAgent"#) key -> do
          !addr <- takeWhileUserAgent
          let !x = UserAgent addr
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

-- Parsing the User Agent is terribly because user agents often
-- have commas in them. So, we use a terrible hack where we look
-- for a comma that is followed by a space and a capital C, and
-- that comma marks the end of the user agent. This works because
-- User Agent is followed by Client.
takeWhileUserAgent :: Parser () s Bytes
takeWhileUserAgent = do
  start <- Unsafe.cursor
  let go = do
        txt <- Latin.skipTrailedBy () ','
        _ <- Latin.char () ' '
        Parser.peek' () >>= \case
          0x43 -> Unsafe.unconsume 2
          c -> go
  go
  -- After go, we are right before the comma.
  end <- Unsafe.cursor
  arr <- Unsafe.expose
  pure $! Bytes arr start (end - start)

skipSyslogPriority :: Parser () s ()
skipSyslogPriority = Latin.trySatisfy (== '<') >>= \case
  True -> do
    Latin.skipDigits1 ()
    Latin.char () '>'
  False -> pure ()

-- Dates look like: YYYY-MM-DDTHH:MM:SSZ
getInitialDate :: Parser () s Chronos.Datetime
getInitialDate = do
  y <- Latin.decWord64 ()
  Latin.char () '-'
  m' <- Latin.decWord64 ()
  m <- case m' of
    0 -> Parser.fail ()
    x | x > 12 -> Parser.fail ()
    _ -> pure (m' - 1)
  Latin.char () '-'
  d <- Latin.decWord64 ()
  Latin.char () 'T'
  h <- Latin.decWord64 ()
  Latin.char () ':'
  mn <- Latin.decWord64 ()
  Latin.char () ':'
  s <- Latin.decWord64 ()
  Latin.char () 'Z'
  pure $ Chronos.Datetime
    (Chronos.Date
      (Chronos.Year (fromIntegral y))
      (Chronos.Month (fromIntegral m))
      (Chronos.DayOfMonth (fromIntegral d))
    )
    (Chronos.TimeOfDay
      (fromIntegral h)
      (fromIntegral mn)
      (1_000_000_000 * fromIntegral s)
    )
