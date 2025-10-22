(ns demo.code-injection-demo
  "A small demo file containing both insecure patterns (that should be flagged by the
   Aikido clj-code-injection rule) and a secure, compliant example for comparison.

   Insecure functions intentionally use `eval`, `read-string`, `load-string`, and `resolve`.
   These should trigger the rule and are suitable for a demo of Aikido Code Quality."
  (:require [clojure.edn :as edn]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Insecure examples — these are intended to be flagged by the custom rule
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; 1) Direct eval of user input (classic, high-risk)
(defn insecure-eval
  "Danger: directly eval'ing user input."
  [user-input]
  ;; Should be flagged: eval + read-string used with untrusted input
  (eval (read-string user-input)))

;; 2) load-string on a raw body (also high-risk)
(defn insecure-load-string
  "Danger: load-string on raw input body."
  [body]
  ;; Should be flagged: load-string used with untrusted input
  (load-string body))

;; 3) resolve used with user-provided operation symbol (semi-dynamic/resolution risk)
(defn insecure-resolve-op
  "Danger: resolving a symbol derived from user input then invoking it."
  [params]
  ;; Example params shape: {:op :add}
  (let [op (:op params)]
    ;; Should be flagged: resolve called on a symbol derived from input
    ((resolve (symbol (name op))) 2 3)))

;; 4) Another variant that reads params from a request-like map
(defn insecure-from-request
  "Danger: using read-string on a query param and then eval'ing it."
  [request]
  ;; request is assumed to be a map with keys like :query or :body
  (let [payload (get-in request [:query :code])]
    ;; Should be flagged: read-string / eval usage on something named like query/body/params
    (when payload
      (eval (read-string payload)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Safe/compliant example — static whitelist mapping (no dynamic resolve/eval)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def operations
  "Explicit static lookup map mapping permitted operation keys to functions."
  {:add +,
   :subtract -,
   :multiply *,
   :divide /})

(defn safe-operation
  "Safe: use an explicit static map rather than resolve/eval/read-string/load-string."
  [op]
  (if-let [f (get operations op)]
    (f 2 3)
    (throw (ex-info "Invalid operation" {:input op}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Demo runner helpers (not required — just to show usage)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn demo-run []
  (println "=== Demo: insecure and secure examples ===")
  (try
    (println "insecure-eval ->" (insecure-eval "(+ 1 2)"))
    (catch Exception e (println "insecure-eval raised:" (.getMessage e))))
  (try
    (println "insecure-load-string ->" (insecure-load-string "(+ 3 4)"))
    (catch Exception e (println "insecure-load-string raised:" (.getMessage e))))
  (try
    (println "insecure-resolve-op ->" (insecure-resolve-op {:op :+}))
    (catch Exception e (println "insecure-resolve-op raised:" (.getMessage e))))
  (try
    (println "safe-operation ->" (safe-operation :add))
    (catch Exception e (println "safe-operation raised:" (.getMessage e)))))

;; When run with `lein run` or similar, call demo-run to see behavior:
;; (demo-run)
