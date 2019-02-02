(ns bitcoinnode.codec
  (:require [bitcoinnode.core :refer :all]
            [clojure.core.async :as async])
  (:import [java.net InetAddress]))


(defn decode-version-cmd>=70001 [version cmd in]
  (if (>= version 70001)
    (assoc 
      cmd :relay (if (= (read-int in 1) 0) false true))
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

(defmethod decode-cmd "version" [_ _ in] 
  (let [cmd {:version (read-version in)
             :services (read-services in)
             :timestamp (read-timestamp in 8)
             :addr-recv (read-network-address in true)
             }
     version (:version cmd)
     ]
    (decode-version-cmd>=106 version cmd in)))
    
(defmethod decode-cmd "verack" [_ _ in]
  {}
  )

(defmethod decode-cmd "alert" [_ _ in]
  {}
  )
(defmethod decode-cmd "ping" [_ _ in]
  {:nounce (read-int in 8 :big)} 
  )

(defmethod decode-cmd "addr" [_ version in]
  (let [n (read-var-int in)
        b (< version 31402)]
     (map (fn [_] (read-network-address in b)) (range n))))

(defmethod decode-cmd "getheaders" [_ _ in]
  {:version (read-version in)
   :hash-count (read-var-int in)
   }
  )

(defn inv-vector [in _]
    {:type (read-int in 4 :big)
     :hash (read-bytes in 32)})

(defmethod decode-cmd "inv" [_ _ in]
  (let [n (read-var-int in)]
    {:inventory (map (partial inv-vector in) (range n))}))

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
   (int->bytes (:relay pl) 1 :little)
    []))

(defmethod encode-cmd "version" [_ payload]
  (let [version (:version payload)]
    (concat
      (int->bytes version 4 :big) 
      (int->bytes (services->int (:services payload)) 8 :big)
      (int->bytes (:timestamp payload) 8 :little)
      (network-address->bytes (:addr-recv payload) true)
      (encode-version-cmd>=106 version payload)
      (encode-version-cmd>=70001 version payload)
      )))

(defmethod encode-cmd "verack" [_ _]
  [])

(defmethod encode-cmd "getaddr" [_ _]
  [])
  
(defmethod encode-cmd "pong" [_ payload]
  (int->bytes (:nounce payload) 8 :big))

(def ver-ack-msg 
  {:cmd "verack", :payload 
   {}})

(def getaddr-msg 
  {:cmd "getaddr", :payload 
   {}})

(def a-ver-msg 
  {:cmd "version", :payload 
   {:version 60002, 
    :timestamp (curr-time-in-sec) 
    :services {:node-network true, 
               :node-get-utxo true,
               :node-bloom true,
               :node-witness true
               :node-network-limited true}
    :nounce (nounce)
    :user-agent "bixus"
    :start-height 212672
    :relay 0
    :addr-from
    {:time 0, :ip (vec (.getAddress (InetAddress/getLocalHost))), 
     :port 8333}
    :addr-recv
    {:time 0, :ip [103 80 168 57], 
     :port 8333}}})



(defn handshake [host net]
  (let [s (open-socket host 8333)
        out (:out s)
        in (:in s)]
    (write-msg!  
      (msg->bytes 
        (assoc a-ver-msg :addr-from {:time (curr-time-in-sec), :ip (ip-str->coll host), 
                                     :port 8333}) net) out)
    (let [rec-ver (dbg (read-msg in 0 net))
          version (:version rec-ver)]
      (when (not= (:cmd rec-ver) "version") (error "Received incorrect version message"))  
      (let [rec-verack (read-msg in version net)]
        (when (not= (:cmd rec-verack) "verack") (error "Received incorrect verack message"))  
        (write-msg! (msg->bytes ver-ack-msg net) out)
        (assoc s :rec-ver rec-ver, :rec-verack rec-verack)))))
        
      
(defmulti react (fn [msg con] (:cmd msg)))

(defmethod react "inv" [msg _]
  )

(defmethod react "alert" [msg _]
  (dbg msg))
(defmethod react "addr" [msg _]
  (dbg msg))
(defmethod react "getheaders" [msg _]
  (dbg msg))

(defmethod react "ping" [msg con]
  (let [out (:out con)]
    (dbg msg)
    (write-msg! (msg->bytes {:cmd "pong", :payload {:nounce (-> msg :payload :nounce)}} (-> con :rec-ver :magic)) out)))

    
(defn read-cmd-proc [con version]
  (let [in (:in con)]
    (async/go
      (while true
        (react (read-msg in version mainnet) con)))))  

(comment 
(def con (handshake "103.80.168.57" mainnet))
(read-cmd-proc con (-> con :rec-ver :payload :version))
)

