(ns bitcoinnode.core
  (:use [clojure.pprint])
  (:import [java.net Socket]
           [java.io BufferedInputStream BufferedOutputStream ByteArrayInputStream]
           [java.nio.charset StandardCharsets]
           [java.time Instant]
           [java.nio.charset StandardCharsets]
           [org.apache.commons.codec.binary Hex]
           [java.security MessageDigest]))
(defmacro dbg [body]
  `(let [x# ~body]
     (println "dbg:" '~body "=" x#)
     x#))

(defn pad [n coll val]
  (take n (concat coll (repeat val))))

(defn endian-of [r endian]
  (condp = endian
	  :little
	  r
	  :big
	  (reverse r)))


(defn bytes->int [bytes endian]
    (reduce (fn [acc v] (bit-or (bit-shift-left acc 8) v)) (endian-of bytes endian)))

(defn invert-endian [endian]
  (condp = endian
    :little :big
    :big :little))

(defn int->bytes [value nr-of-bytes endian]
    (map #(bit-and (bit-shift-right value (* % 8)) 0xff) (endian-of (range nr-of-bytes) (invert-endian endian))))

(def sha-256 (MessageDigest/getInstance "SHA-256"))

(defn bytes->sha256 [bytes]
    (.digest sha-256 bytes))

(defn bytes->unsigned [bytes]
  (map #(bit-and % 0xff) bytes))


(defn calc-checksum-as-bytes [bytes]
  (let [cs (bytes->unsigned (->> bytes bytes->sha256 bytes->sha256 (take 4)))]
    (map #(Integer/toString % 16) cs)
    cs))

(defn calc-checksum [bytes]
  (bytes->int (calc-checksum-as-bytes bytes) :little))
  



(defn read-bytes [in n] 
  (let [bytes (byte-array n)]
    (.read in bytes)
    (bytes->unsigned bytes)))

(defn read-int 
  ([in nr-of-bytes endian]
  (bytes->int (read-bytes in nr-of-bytes) endian))
  ([in nr-of-bytes]
    (read-int in nr-of-bytes :little)))

(defn read-bool [in]
  (read-int in 1))

(defn read-var-int [in]
  (let [first-byte (read-int in 1)]
    (cond 
      (= first-byte 0xff) (read-int in 8)
      (= first-byte 0xfe) (read-int in 4)
      (= first-byte 0xfd) (read-int in 2)
      :else
      first-byte)))
  
(defn read-var-str [in]
  (let [n (read-var-int in)]
    (String. (byte-array (read-bytes in n)) StandardCharsets/US_ASCII)))

(defn str->var-bytes [s]
  (let [n (count s)
        bytes (.getBytes s)]
    (cond 
      (< n 0xfd) (concat [n] bytes)
      (<= n Short/MAX_VALUE) (concat [0xfd] (int->bytes n 2 :little) bytes) 
      (<= n Short/MAX_VALUE) (concat [0xfe] (int->bytes n 4 :little) bytes)
      :else (concat [0xff] (int->bytes n 8 :little) bytes)
    )))

(defn read-timestamp [in nr-of-bytes]
  (read-int in nr-of-bytes))


(defn read-magic [in]
  (read-int in 4 :big))

(defn read-cmd [in]
  (String. (byte-array (take-while #(> % 0) (read-bytes in 12))) StandardCharsets/US_ASCII))
  
(defn cmd->bytes [cmd]
  (pad 12 (.getBytes cmd) 0))
  

(defn read-length [in]
  (read-int in 4 :big))

(defn read-checksum [in]
  (read-int in 4))

(defn read-payload [in n checksum]
  (let [pl (byte-array (read-bytes in n))]
    ;(ByteArrayInputStream. (byte-array pl))
    (if (= (calc-checksum pl) checksum)
      (ByteArrayInputStream. pl)
      (throw (IllegalStateException. "Wrong checksum in payload")))))


(defn int->services [v]
  {:node-network (= (bit-and v 0x1) 0x1)
     :node-get-utxo (= (bit-and v 0x2) 0x2)
     :node-bloom (= (bit-and v 0x4) 0x4)
     :node-witness (= (bit-and v 0x8) 0x8)
     :node-network-limited (= (bit-and v 1024) 1024)})

(defn services->int [services]
  (bit-or
    (if (:node-network services) 1 0)
    (if (:node-get-utxo services) 2 0)
    (if (:node-bloom services) 4 0)
    (if (:node-witness services) 8 0)
    (if (:node-network-limited services) 1024 0)
    ))

(defn read-services [in]
  (int->services (read-int in 8 :big)))


;(defn bytes->ip [bytes]

(defn read-ip [in]
  (doseq [b (read-bytes in 10)]
    (when (not= b 0) (throw (IllegalStateException. (format "byte should be 0 but is %s" b)))))
  (doseq [b (read-bytes in 2)]
    (when (not= b 255) (throw (IllegalStateException. (format "byte should be 255 but is %s" b)))))
   (dbg (read-bytes in 4)))

(defn ip->bytes [ip]
  (concat
    [0 0 0 0 0 0 0 0 0 0 0xff 0xff]
    ip))

(defn read-port [in]
  (read-int in 2 :big))

(defn read-network-address 
  ([in version-cmd?]
  ;TODO time  
  {:time (when (not version-cmd?) (read-timestamp in 4))
   :services (read-services in)
   :ip (read-ip in)
   :port (read-port in)
   }
  )
  ([in]
    (read-network-address in false)))

(defn network-address->bytes 
  ([addr version-cmd?]
  ;TODO time  
  (concat
    (if version-cmd? [] (int->bytes (:time addr) 4 :little))
    (int->bytes (services->int (:services addr)) 8 :big)
    (ip->bytes (:ip addr))
    (int->bytes (:port addr) 2 :big)
    )
  )
  ([addr]
    (network-address->bytes addr false)))
    
                              

(defn read-version [in]
  (read-int in 4 :big))

(defmulti decode-cmd (fn [cmd in] cmd))
(defmulti encode-cmd (fn [cmd payload] cmd))


(defn read-msg [in magic]
  (let [m (read-magic in)]
    (if (= m magic)
      (let [m {:magic m
               :cmd (read-cmd in)
               :length (read-length in)
               :checksum (read-checksum in)
               }
            ]
        (assoc m :payload (decode-cmd (:cmd m) (read-payload in (:length m) (:checksum m)))))
      (throw (IllegalStateException. "Wrong network magic value")))))
  

(defn msg->bytes [msg magic]
  (let [payload (encode-cmd (:cmd msg) (:payload msg))]
    (concat 
      (int->bytes magic 4 :big)
      (cmd->bytes (:cmd msg))
      (int->bytes (count payload) 4 :big)
      (calc-checksum-as-bytes (byte-array payload))
      payload
      ))) 


(defn write-msg! [data out]
  (.write out (byte-array data)))
  
(defn decode-version-cmd>=70001 [version cmd in]
  (if (>= version 70001)
    (assoc 
      cmd)
    cmd))
  

(defn decode-version-cmd>=106 [version cmd in]
  (if (>= version 106)
    (decode-version-cmd>=70001 version
      (assoc cmd
        :addr-from (read-network-address in true)
        :nounce (read-int in 8 :big) 
        :user-agent (read-var-str in)
        :start-height (read-int in 4 :big))
      in)
    cmd))

(defmethod decode-cmd "version" [_ in] 
  (let [cmd {:version (read-version in)
             :services (read-services in)
             :timestamp (read-timestamp in 8)
             :addr-recv (read-network-address in true)
             }
     version (:version cmd)
     ]
    (decode-version-cmd>=106 version cmd in)))
    


(defn encode-version-cmd>=106 [version pl]
  (if (>= version 106)
    (concat
      (network-address->bytes (:addr-from pl) true)
      (int->bytes (:nounce pl) 8 :big)
      (str->var-bytes (:user-agent pl))
      (int->bytes (:start-height pl) 4 :big)
      )
    []))

(defn encode-version-cmd>=70001 [version pl]
  (if (>= version 70001)
   ; (int->bytes (:relay pl) 1 :little)
    []))

(defmethod encode-cmd "version" [_ payload]
  (let [version (:version payload)]
    (concat
      (int->bytes version 4 :big) 
      (int->bytes (services->int (:services payload)) 8 :big)
      (int->bytes (:timestamp payload) 8 :little)
      (network-address->bytes (:addr-recv payload) true)
      (encode-version-cmd>=106 version payload)
;      (encode-version-cmd>=70001 version payload)
      )))
                  
  

(defn open-socket [host port]
  (let [s (Socket. host port)]
    {:socket s
     :in (BufferedInputStream. (.getInputStream s))
     :out (BufferedOutputStream. (.getOutputStream s))}
    ))

(def mainnet 0xD9B4BEF9)
(def testnet3 0x0709110B)


(defn send-ver-msg [s ver-msg]
  (.write (:out s) (byte-array (msg->bytes ver-msg mainnet)))
  (.flush (:out s))
  (let [ba (byte-array 200)]
    (.read (:in s) ba)
    (dbg (map #(Integer/toString % 16) (bytes->unsigned ba)))
    (read-msg (ByteArrayInputStream. ba) mainnet)))

(def a-ver-msg 
  {:cmd "version", :payload 
   {:version 60002, 
    :timestamp (.getEpochSecond (Instant/parse "2012-12-18T02:12:33.00Z")) 
    :services {},
    :nounce (long (rand Long/MAX_VALUE))
    :user-agent "Satoshi:0.7.2"
    :start-height 212672
    :relay 0
    :addr-from
    {:time 0, :ip [88 129 173 173], 
     :port 8333}
    :addr-recv
    {:time 0, :ip [103 80 168 57], 
     :port 8333}}})



   
                            