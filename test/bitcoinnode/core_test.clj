(ns bitcoinnode.core-test
  (:require [clojure.test :refer :all]
            [bitcoinnode.core :refer :all])
  (:import [java.io ByteArrayInputStream]))


(def valid-payload    
  [0x62 0xEA 0x00 0x00                                                                   ; 60002 (protocol version 60002)
   0x01 00 00 00 00 00 00 00                                                       ; 1 (NODE_NETWORK services)
   0x11 0xB2 0xD0 0x50 00 00 00 00                                                       ; Tue Dec 18 10:12:33 PST 2012
   0x01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0xFF 0xFF 00 00 00 00 00 00 ; Recipient address info - see Network Address
   0x01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0xFF 0xFF 00 00 00 00 00 00 ; Sender address info - see Network Address
   0x3B 0x2E 0xB3 0x5D 0x8C 0xE6 0x17 0x65                                                       ; Node ID
   0x0F 0x2F 0x53 0x61 0x74 0x6F 0x73 0x68 0x69 0x3A 0x30 0x2E 0x37 0x2E 0x32 0x2F                               ; "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
   0xC0 0x3E 0x03 0x00])

(def valid-ver-msg 
  (concat
    [0xF9 0xBE 0xB4 0xD9                                                                   ;Main network magic bytes
     0x76 0x65 0x72 0x73 0x69 0x6F 0x6E 0x00 0x00 0x00 0x00 0x00                                           ;"version" command
     0x64 0x00 0x00 0x00                                                                   ;Payload is 100 bytes long
     0x35 0x8d 0x49 0x32]
    valid-payload))


(deftest decode-roundtrip 
  (is (= valid-ver-msg (msg->bytes (read-msg (ByteArrayInputStream. (byte-array valid-ver-msg)) mainnet) mainnet))))



 
