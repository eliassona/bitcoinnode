(ns bitcoinnode.core
  (:import [java.net Socket]
           [java.io BufferedInputStream BufferedOutputStream]
           [java.nio.charset StandardCharsets]
           [java.security MessageDigest]))


(defn endian-of [r endian]
  (condp = endian
	  :little
	  r
	  :big
	  (reverse r)))


(defn bytes->int [bytes endian]
    (reduce (fn [acc v] (bit-or (bit-shift-left acc 8) v)) (endian-of bytes endian)))
  
(defn int->bytes [value nr-of-bytes endian]
    (map #(bit-and (bit-shift-right value (* % 8)) 0xff) (endian-of (range nr-of-bytes) endian)))

(def sha-256 (MessageDigest/getInstance "SHA-256"))

(defn bytes->sha256 [bytes]
    (.update sha-256 bytes)
    (.digest sha-256))

(defn calc-checksum [bytes]
  (->> bytes bytes->sha256 bytes->sha256 (take 4)))
  

(defn open-socket [host port]
  (let [s (Socket. host port)]
    {:socket s
     :in (BufferedInputStream. (.getInputStream s))
     :out (BufferedOutputStream. (.getOutputStream s))}
    ))


(defn read-bytes [in n] 
  (let [bytes (byte-array n)]
    (.read in bytes)
    bytes))

(defn read-magic [in]
  (bytes->int (read-bytes in 4) :little))

(defn read-cmd [in]
  (String. (read-bytes in 12) StandardCharsets/US_ASCII))
  
(defn read-length [in]
  (bytes->int (read-bytes in 4) :little))

(defn read-checksum [in]
  (read-bytes in 4))

(defn read-payload [in n checksum]
  (let [pl (read-bytes in n)]
    (if (= (calc-checksum pl) checksum)
      pl
      (throw (IllegalStateException. "Wrong checksum in payload")))))
  

(defn read-msg [in]
  (let [m {:magic (read-magic in)
           :cmd (read-cmd in)
           :length (read-length in)}
        ]
    (assoc m :payload (read-payload in (:length m)))))
  

(def mainnet 0xD9B4BEF9)
(def testnet3 0x0709110B)