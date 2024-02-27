{-# language BangPatterns #-}
{-# language DerivingStrategies #-}
{-# language NamedFieldPuns #-}
{-# language NumericUnderscores #-}
{-# language MagicHash #-}
{-# language LambdaCase #-}
{-# language DeriveAnyClass #-}
{-# language MultiWayIf #-}

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
import Data.Bytes.Patterns

import qualified Cisco.Ftd.Syslog.Patterns as Patterns
import qualified Chronos
import qualified Net.IPv4 as IPv4
import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.Unsafe as Unsafe

data Message = Message
  { time :: !Chronos.Datetime
  , severity :: !Word64
  , number :: !Word64
  , attributes :: !(Chunks Attribute)
  }

data Attribute
  = AcPolicy {-# UNPACK #-} !Bytes
  | AccessControlRuleAction {-# UNPACK #-} !Bytes
  | AccessControlRuleName {-# UNPACK #-} !Bytes
  | AccessControlRuleReason {-# UNPACK #-} !Bytes
  | ApplicationProtocol {-# UNPACK #-} !Bytes
  | Client {-# UNPACK #-} !Bytes
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
  | IpsCount {-# UNPACK #-} !Word64
  | NapPolicy {-# UNPACK #-} !Bytes
  | Protocol {-# UNPACK #-} !Bytes
  | ReferencedHost {-# UNPACK #-} !Bytes
  | ResponderBytes !Word64
  | ResponderPackets !Word64
  | SourceIp !IPv4
  | SourcePort !Word16
  | Url {-# UNPACK #-} !Bytes
  | UrlCategory {-# UNPACK #-} !Bytes
  | UrlReputation {-# UNPACK #-} !Bytes
  | UserAgent {-# UNPACK #-} !Bytes
  | WebApplication {-# UNPACK #-} !Bytes
  deriving stock (Eq,Show)

decode :: Bytes -> Maybe Message
decode b = Parser.parseBytesMaybe parser b

parser :: Parser () s Message
parser = do
  skipSyslogPriority
  Latin.skipWhile (==' ')
  -- Sometimes, there is no datetime after the priority. In this case,
  -- we set the timestamp to the UNIX epoch.
  time <- Latin.peek' () >>= \case
    '%' -> pure $! Chronos.timeToDatetime Chronos.epoch
    _ -> getInitialDate <* Latin.skipChar1 () ' '
  -- Sometimes, there is only space between the timestamp and the %FTD.
  -- But sometimes, there is a colon in the middle of the space for
  -- no evident reason.
  Latin.trySatisfy (== ':') >>= \case
    False -> pure ()
    True -> Latin.skipChar ' '
  Parser.cstring () (Ptr "%FTD-"#)
  severity <- Latin.decWord64 ()
  Latin.char () '-'
  number <- Latin.decWord64 ()
  Latin.char2 () ':' ' '
  r <- parserKeyValue =<< Parser.effect Builder.new
  pure Message{time,severity,number,attributes=r}
  
parserKeyValue :: Builder s Attribute -> Parser () s (Chunks Attribute)
parserKeyValue !b0 = do
  key <- Latin.takeTrailedBy () ':'
  Latin.char () ' '
  b1 <- if
    | Patterns.isAccessControlRuleAction key -> do
        txt <- Parser.takeWhile (/=0x2C)
        let !x = AccessControlRuleAction txt
        Parser.effect (Builder.push x b0)
    | Patterns.isAccessControlRuleName key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = AccessControlRuleName txt
      Parser.effect (Builder.push x b0)
    | Patterns.isAccessControlRuleReason key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = AccessControlRuleReason txt
      Parser.effect (Builder.push x b0)
    | Patterns.isApplicationProtocol key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = ApplicationProtocol txt
      Parser.effect (Builder.push x b0)
    | Patterns.isInitiatorPackets key -> do
      !n <- Latin.decWord64 ()
      let !x = InitiatorPackets n
      Parser.effect (Builder.push x b0)
    | Patterns.isResponderPackets key -> do
      !n <- Latin.decWord64 ()
      let !x = ResponderPackets n
      Parser.effect (Builder.push x b0)
    | Patterns.isIngressInterface key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = IngressInterface txt
      Parser.effect (Builder.push x b0)
    | Patterns.isEgressInterface key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = EgressInterface txt
      Parser.effect (Builder.push x b0)
    | Patterns.isInitiatorBytes key -> do
      !n <- Latin.decWord64 ()
      let !x = InitiatorBytes n
      Parser.effect (Builder.push x b0)
    | Patterns.isResponderBytes key -> do
      !n <- Latin.decWord64 ()
      let !x = ResponderBytes n
      Parser.effect (Builder.push x b0)
    | Patterns.isIngressZone key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = IngressZone txt
      Parser.effect (Builder.push x b0)
    | Patterns.isURLCategory key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = UrlCategory txt
      Parser.effect (Builder.push x b0)
    | Patterns.isURLReputation key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = UrlReputation txt
      Parser.effect (Builder.push x b0)
    | Patterns.isEgressZone key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = EgressZone txt
      Parser.effect (Builder.push x b0)
    | Patterns.isClient key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = Client txt
      Parser.effect (Builder.push x b0)
    | Patterns.isWebApplication key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = WebApplication txt
      Parser.effect (Builder.push x b0)
    | Patterns.isReferencedHost key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = ReferencedHost txt
      Parser.effect (Builder.push x b0)
    | Patterns.isUserAgent key -> do
      !addr <- takeWhileUserAgent
      let !x = UserAgent addr
      Parser.effect (Builder.push x b0)
    | Patterns.isSrcPort key -> do
      !addr <- Latin.decWord16 ()
      let !x = SourcePort addr
      Parser.effect (Builder.push x b0)
    | Patterns.isDstPort key -> do
      !addr <- Latin.decWord16 ()
      let !x = DestinationPort addr
      Parser.effect (Builder.push x b0)
    | Patterns.isProtocol key -> do
      txt <- Parser.takeWhile (/=0x2C)
      let !x = Protocol txt
      Parser.effect (Builder.push x b0)
    | Patterns.isSrcIP key -> do
      !addr <- IPv4.parserUtf8Bytes ()
      let !x = SourceIp addr
      Parser.effect (Builder.push x b0)
    | Patterns.isDstIP key -> do
      !addr <- IPv4.parserUtf8Bytes ()
      let !x = DestinationIp addr
      Parser.effect (Builder.push x b0)
    | Patterns.isURL key -> do
      !txt <- Parser.remaining
      case Bytes.any (==0x20) txt of
        True -> Parser.fail ()
        False -> do
          let !x = Url txt
          Parser.effect (Builder.push x b0)
    | otherwise -> do
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
