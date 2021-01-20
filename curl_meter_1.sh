curl --location --request PUT 'http://10.0.48.43:8181/restconf/config/opendaylight-inventory:nodes/node/openflow:147059310694/flow-node-inventory:meter/1' \
--header 'Authorization: Basic YWRtaW46YWRtaW4=' \
--header 'Content-Type: application/json' \
--data-raw '{
 "meter": [{
  "flags": "meter-kbps meter-burst meter-stats",
  "meter-band-headers": {
   "meter-band-header": [{
    "band-burst-size": "512",
    "band-id": "1",
    "band-rate": "4096",
    "drop-burst-size": "512",
    "drop-rate": "256",
    "meter-band-types": {
     "flags": "ofpmbt-drop"
    }
   }]
  },
  "meter-id": "1",
  "meter-name": "abc"
 }]
}'