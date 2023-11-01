module Sample
  ( sample1
  , sample2
  , sample3
  , sample4
  ) where

import Data.Bytes (Bytes)
import qualified Data.Bytes as Bytes

sample1 :: Bytes
sample1 = Bytes.fromLatinString
  "<185>2020-07-24T13:13:45Z   %FTD-1-430003: DeviceUUID:\
  \ 854f1702-0ecf-1de8-0df9-e7e6f1185fdb, AccessControlRuleAction:\
  \ Allow, SrcIP: 192.0.2.143, DstIP: 192.0.2.74, SrcPort: 48522,\
  \ DstPort: 80, Protocol: tcp, IngressInterface: Outside, EgressInterface:\
  \ VX-DMZ, IngressZone: My-Outside, EgressZone: My-Inside, ACPolicy:\
  \ My ASA Policy, AccessControlRuleName: MyFromOutsideRule, Prefilter\
  \ Policy: CCSO, User: No Authentication Required, UserAgent: Mozilla/5.0\
  \ (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)\
  \ Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586, Client: Edge,\
  \ ClientVersion: 13.10586, ApplicationProtocol: HTTP, WebApplication:\
  \ Squid, ConnectionDuration: 0, InitiatorPackets: 11, ResponderPackets:\
  \ 6, InitiatorBytes: 7023, ResponderBytes: 875, NAPPolicy: Network Analysis\
  \ Policy, HTTPResponse: 302, HTTPReferer: http://example.\
  \com/foo/bar, ReferencedHost:\
  \ example.com, URLCategory: Government, URLReputation: Well\
  \ known, URL: http://example.com/foo.aspx"

-- TODO: Are SFIMS and FTD logs really even the same thing?
sample2 :: Bytes
sample2 = Bytes.fromLatinString
  "Mar  2 18:14:17 ccso911-asa-ftd1 SFIMS: Protocol: ICMP, SrcIP:\
  \ 192.0.2.209, OriginalClientIP: ::, DstIP: 192.0.2.105, ICMPType:\
  \ Echo Request, ICMPCode: No Code, TCPFlags: 0x0, IngressZone: Zone-Outside,\
  \ EgressZone: Zone-DMZ, DE: Primary Detection Engine\
  \ (855f1722-a2c4-10e8-95f9-e7e5f159521e), Policy: Example ASA5525-HA FTD,\
  \ ConnectType: End, AccessControlRuleName: FromOutside - P2C,\
  \ AccessControlRuleAction: Allow, Prefilter Policy: Default Prefilter\
  \ Policy, Client: ICMP client, ApplicationProtocol: ICMP, InitiatorPackets:\
  \ 1, ResponderPackets: 1, InitiatorBytes: 50, ResponderBytes: 50, NAPPolicy:\
  \ Network Analysis Policy, DNSResponseType: No Error, Sinkhole: Unknown,\
  \ URLCategory: Unknown, URLReputation: Risk unknown"

sample3 :: Bytes
sample3 = Bytes.fromLatinString
  "<185>2020-09-16T13:33:17Z   %FTD-1-430002: DeviceUUID:\
  \ 744c08f0-1fe4-02b7-6eaa-fe64390ba2f0, AccessControlRuleAction: Block,\
  \ SrcIP: 192.0.2.12, DstIP: 192.0.2.118, SrcPort: 41810, DstPort: 465,\
  \ Protocol: tcp, IngressInterface: Outside, EgressInterface: DMZ,\
  \ IngressZone: Zone-Outside, EgressZone: Zone-DMZ, ACPolicy:\
  \ My Policy Name, AccessControlRuleName: Default Action, Prefilter\
  \ Policy: Foo, User: No Authentication Required, InitiatorPackets: 0,\
  \ ResponderPackets: 0, InitiatorBytes: 0, ResponderBytes: 0, NAPPolicy:\
  \ Balanced Security and Connectivity"

sample4 :: Bytes
sample4 = Bytes.fromLatinString
  "<185>%FTD-1-430002: DeviceUUID:\
  \ 744c08f0-1fe4-02b7-6eaa-fe64390ba2f0, AccessControlRuleAction: Block,\
  \ SrcIP: 192.0.2.12, DstIP: 192.0.2.118, SrcPort: 41810, DstPort: 465,\
  \ Protocol: tcp, IngressInterface: Outside, EgressInterface: DMZ,\
  \ IngressZone: Zone-Outside, EgressZone: Zone-DMZ, ACPolicy:\
  \ My Policy Name, AccessControlRuleName: Default Action, Prefilter\
  \ Policy: Foo, User: No Authentication Required, InitiatorPackets: 0,\
  \ ResponderPackets: 0, InitiatorBytes: 0, ResponderBytes: 0, NAPPolicy:\
  \ Balanced Security and Connectivity"
