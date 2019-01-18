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

["f9" "be" "b4" "d9" 
 "76" "65" "72" "73" "69" "6f" "6e" "0" "0" "0" "0" "0" 
 "66" "0" "0" "0" 
 "ed" "b3" "e5" "18" 
 "7f" "11" "1" "0" 
 "d" "4" "0" "0" "0" "0" "0" "0" 
 "89" "85" "41" "5c" "0" "0" "0" "0" 
 "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "ff" "ff" "d4" "10" "b0" "1a" "16" "3a" 
 "d" "4" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "94" "94" "e0" "96" "8e" "b3" "54" "a6" "10" "2f" "53" "61" "74" "6f" "73" "68" "69" "3a" "30" "2e" "31" "37" "2e" "30" "2f" "99" "87" "8" "0" "1" "f9" "be" "b4" "d9" "76" "65" "72" "61" "63" "6b" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "5d" "f6" "e0" "e2" "f9" "be" "b4" "d9" "61" "6c" "65" "72" "74" "0" "0" "0" "0" "0" "0" "0" "a8" "0" "0" "0" "1b" "f9" "aa" "ea" "60" "1" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "ff" "ff" "ff" "7f" "0" "0" "0" "0" "ff" "ff" "ff" "7f" "fe"]

(def real-reply-from-39-106-249-60 [249 190 180 217 118 101 114 115 105 111 110 0 0 0 0 0 102 0 0 0 237 179 229 24 127 17 1 0 13 4 0 0 0 0 0 0 137 133 65 92 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 212 16 176 26 22 58 13 4 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 148 148 224 150 142 179 84 166 16 47 83 97 116 111 115 104 105 58 48 46 49 55 46 48 47 153 135 8 0 1 249 190 180 217 118 101 114 97 99 107 0 0 0 0 0 0 0 0 0 0 93 246 224 226 249 190 180 217 97 108 101 114 116 0 0 0 0 0 0 0 168 0 0 0 27 249 170 234 96 1 0 0 0 0 0 0 0 0 0 0 0 255 255 255 127 0 0 0 0 255 255 255 127 254])
(deftest decode-roundtrip 
  (is (= valid-ver-msg (msg->bytes (read-msg (ByteArrayInputStream. (byte-array valid-ver-msg)) mainnet) mainnet))))



 
