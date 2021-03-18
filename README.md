
# multiqueue traffic generator

mq.py traffic generator(based on trex) helps to evaluate multiqueue behaviour of the DUT by generating flow that are asymmetric, so that the queues on the DUT are asymmetrically loaded.
It uses  2 phased approach for asymmetric traffic generation

phase 1, learning, use scapy to generate the range of traffic,  collect and sort into queues

phase 2, generate traffic using trex with above classified flow pattern. 

For example, below command triggers the learning phase.
```
 ./mq.py  --fps 10   --interfaces eth1 eth2 --qratio '{"q": 0, "pps": ".4", "isg": 0}'  '{"q": 1, "pps": ".6", "isg": 0}' '{"q": 2, "pps": ".2", "isg": 0}'  --gen-learning 0 10
```
On the DUT testpmd is started with ` fwd rxonly` mode and `port config all rss all` and verbose set, to log all the traffic received by testpmd along with the queue information.

In phase 2, below command is used to parse the above generated testpmd log and generate queue to IP mapping, which in turn is used to generate asymmetric flows based on qratio.
```
 ./mq.py  --fps 20   --interfaces eth1 eth2 --qratio '{"q": 0, "pps": ".4", "isg": 0}'  '{"q": 1, "pps": ".6", "isg": 0}' '{"q": 2, "pps": ".2", "isg": 0}'   --gen-traffic --duration  120 --multiplier 1

```

An example of the generated queue to IP mapping extracted from testpmd log.
```
pkt_mapping =
{ "0": [ "16.0.0.1", "16.0.0.3", "16.0.0.5" ], "1": [ "16.0.0.6", "16.0.0.8" ], "2": [ "16.0.0.2", "16.0.0.4", "16.0.0.7", "16.0.0.9" ] }
```
With queue rato of  `'{"q": 0, "pps": ".4", "isg": 0}'  '{"q": 1, "pps": ".6", "isg": 0}' '{"q": 2, "pps": ".2", "isg": 0}' `

.5 mpps packets would generated for queue 0 and .6 mpp , .2 mpps for queue 1 and queue 2 respectively. 
