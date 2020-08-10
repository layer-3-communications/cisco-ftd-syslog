import Gauge (bench,whnf,defaultMain)

import qualified Sample as S
import qualified Cisco.Ftd.Syslog as Cisco

main :: IO ()
main = defaultMain
  [ bench "Sample1" (whnf Cisco.decode S.sample1)
  ]

