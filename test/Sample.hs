module Sample
  ( sample1
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
