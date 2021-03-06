(ns bitcoinnode.core
  (:use [clojure.pprint]
        [clojure.repl])
  (:import [java.net Socket InetAddress]
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

(defn error [msg]
  (throw (IllegalStateException. msg)))

(defn curr-time-in-sec []
  (-> (Instant/now) .getEpochSecond))

(defn ip-str->coll [ip]
  (map read-string (.split ip "\\.")))


(defn nounce [] (long (rand Long/MAX_VALUE)))

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
      (error "Wrong checksum in payload"))))

(defn open-socket [host port]
  (let [s (Socket. host port)]
    {:socket s
     :in (BufferedInputStream. (.getInputStream s))
     :out (BufferedOutputStream. (.getOutputStream s))}
    ))

(defn write-msg! [data out]
  (.write out (byte-array data))
  (.flush out))

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


(defn read-ip [in]
  (doseq [b (read-bytes in 10)]
    (when (not= b 0) (error (format "byte should be 0 but is %s" b))))
  (read-bytes in 2)
  ;TODO verification
  #_(doseq [b (read-bytes in 2)]
     (when (not= b 255) (error (format "byte should be 255 but is %s" b))))
   (read-bytes in 4))

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

(defmulti decode-cmd (fn [cmd version in] cmd))
(defmulti encode-cmd (fn [cmd payload] cmd))


(defn read-msg [in version magic]
  (let [m (read-magic in)]
    (if (= m magic)
      (let [m {:magic m
               :cmd (read-cmd in)
               :length (read-length in)
               :checksum (read-checksum in)
               }
            ]
        (assoc m :payload (decode-cmd (:cmd m) version (read-payload in (:length m) (:checksum m)))))
      (error (format "Wrong network magic value, expected %s, actual %s", magic m)))))
  

(defn msg->bytes [msg magic]
  (let [payload (encode-cmd (:cmd msg) (:payload msg))]
    (concat 
      (int->bytes magic 4 :big)
      (cmd->bytes (:cmd msg))
      (int->bytes (count payload) 4 :big)
      (calc-checksum-as-bytes (byte-array payload))
      payload
      ))) 

(def mainnet 0xD9B4BEF9)
(def testnet3 0x0709110B)
(def testnet 0xDAB5BFFA)
(def namecoin 0xFEB4BEF9)
  
   
                             