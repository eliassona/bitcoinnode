(ns bitcoinnode.crawl
  (:require [bitcoinnode.core :refer [mainnet dbg read-msg write-msg! msg->bytes]]
            [bitcoinnode.codec :refer [handshake send-pong send-ping]]
            [clojure.core.async :as async])
  )


(defn send-proc! [in-chan out-chan net nodes]
  (async/go
    (while true
      (try 
        (let [ip (async/<! in-chan)]
          (when-not (contains? @nodes ip)
            (async/go
              (try
                (let [con (handshake ip net)]
                  (write-msg! (msg->bytes {:cmd "getaddr", :payload []} net) (:out con))
                  (async/>! out-chan con)
                  (swap! nodes conj ip))
              (catch Exception e
                (println e))))))
        (catch Exception e)))))

(defn next-msg [con net]
  (try 
    (read-msg (:in con) (-> con :payload :version) net)
    (catch Exception e
      (println "got exception")
      ;(next-msg con net)
      )))

(defn addr-proc! [in-chan out-chan net conns]
  (async/go
    (while true
      (try 
        (let [con (async/<! in-chan)]
          (async/go
            (swap! conns conj con)
              (loop [i 0]
                (dbg i)
                (let [msg (next-msg con net)]
;                (dbg (-> con :rec-ver :payload :addr-from :ip))
;                (dbg (-> con :rec-ver :payload :addr-recv :ip))
                (condp = (dbg (:cmd msg))
                "addr"
                (do
                  (doseq [ip (-> msg :payload)]
                    (async/>! out-chan (dbg (:ip ip))))
                  (swap! conns disj con)
                  (.close (:socket con))
                  )
                "ping"
                (do 
                  ;(send-pong msg con)
                  (recur (inc i)))
                (recur (inc i)))))))))))
  

(defn crawl
  "Crawls the bitcoin network.
   Returns an atom with a set of found nodes"
  [ips net]
  (let [nodes (atom #{})
        conns (atom #{})
        ip-chan (async/chan 10)
        con-chan (async/chan 10)]
    (send-proc! ip-chan con-chan net nodes)
    (addr-proc! con-chan ip-chan net conns)
    (async/go
      (doseq [ip ips]
        (async/>! ip-chan ip)))
    {:nodes nodes, :ip-chan ip-chan, :con-chan con-chan, :connections conns}
  ))

(defn close! [res]
  (doseq [c (-> res :connections  deref)]
    (.close (:socket c))))

(comment
  (def res (crawl [] mainnet))
  (async/go (async/>! (:ip-chan res) "52.77.229.135"))
  (send-ping (-> res :connections deref first))
  (def res (crawl ["83.101.34.91" "89.69.221.56" "52.43.125.33" "159.203.183.65" "54.254.164.157" "104.128.228.252"] mainnet)))
