{-# language ViewPatterns #-}
{-# language TemplateHaskell #-}
{-# language PatternSynonyms #-}

module Cisco.Ftd.Syslog.Patterns where

import Data.Bytes.Patterns

makeBytesPatterns
  [ "AccessControlRuleAction"
  , "AccessControlRuleName"
  , "ApplicationProtocol"
  , "InitiatorPackets"
  , "ResponderPackets"
  , "IngressInterface"
  , "EgressInterface"
  , "InitiatorBytes"
  , "ResponderBytes"
  , "IngressZone"
  , "UrlCategory"
  , "EgressZone"
  , "UserAgent"
  , "SrcPort"
  , "DstPort"
  , "Protocol"
  , "SrcIP"
  , "DstIP"
  ]
