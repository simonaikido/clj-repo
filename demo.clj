(ns demo.code-injection-demo-2
  "Second demo file with additional insecure code-injection patterns that should be
   flagged by the clj-code-injection rule (uses of eval, read-string, load-string,
   apply+resolve, and intern). Includes a safe example for comparison."
  (:require [clojure.edn :as edn]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Insecure examples — intentionally vulnerable to trigger scanner
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; 1) eval on concatenated user input (string construction then eval)
(defn insecure-eval-concat
  "Concatenates pieces of user input into code and evaluates it."
  [op-str arg1 arg2]
  ;; Should be flagged: eval used with constructed code from inputs
  (let [code-str (str "(" op-str " " arg1 " " arg2 ")")]
    (eval (read-string code-str))))

;; 2) load-string after reading file content (content may be user-provided)
(defn insecure-load-from-file
  "Reads a file path supplied by a caller and load-strings its contents."
  [path]
  ;; Should be flagged: slurp + load-string on external file content
  (let [content (slurp path)]
    (load-string content)))

;; 3) apply with resolve on user-chosen function name (indirect dynamic invocation)
(defn insecure-apply-resolve
  "Resolves a symbol created from user input and calls it with apply."
  [fn-name args]
  ;; args is expected to be a collection
  ;; Should be flagged: (resolve ...) used to call a function derived from input
  (let [sym (symbol fn-name)
        f   (resolve sym)]
    (apply f args)))

;; 4) using intern to create/replace a var dynamically from input (dangerous)
(defn insecure-intern
  "Uses intern to create or overwrite a var using user input to determine its name."
  [ns-str name-str expr]
  ;; Should be flagged: intern combined with eval/read-string-style usage
  (let [ns-obj (find-ns (symbol ns-str))
        name-sym (symbol name-str)]
    (intern ns-obj name-sym (eval (read-string expr)))))

;; 5) eval after edn/read-string of user payload (still dangerous)
(defn insecure-edn-then-eval
  "Parses EDN then evals its :code field — common pattern that is risky."
  [payload-str]
  ;; Should be flagged: edn/read-string then eval
  (let [payload (edn/read-string payload-str)
        code    (:code payload)]
    (when code
      (eval (read-string code)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Safe/compliant example — explicit dispatch map + whitelisting of file sources
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def safe-ops
  "Static mapping of allowed functions — no dynamic resolution or eval."
  {:add +
   :sub -
   :mul *
   :div /})

(defn safe-dispatch
  "Safe example: choose functions via explicit map and ensure args are coerced."
  [op-key & args]
  (if-let [f (get safe-ops op-key)]
    ;; coerce args to numbers (example) and call f
    (let [nums (mapv #(Double/parseDouble (str %)) args)]
      (apply f nums))
    (throw (ex-info "Invalid operation" {:op op-key}))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Small runner with examples (not required)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn demo-run-2 []
  (println "=== Demo 2: insecure patterns vs safe dispatch ===")
  (try
    (println "insecure-eval-concat ->" (insecure-eval-concat "+ " "1" "2"))
    (catch Exception e (println "insecure-eval-concat raised:" (.getMessage e))))
  (try
    ;; This will likely fail unless you point to a valid file; it's just for demo.
    (println "insecure-load-from-file ->" (insecure-load-from-file "example.clj"))
    (catch Exception e (println "insecure-load-from-file raised:" (.getMessage e))))
  (try
    (println "insecure-apply-resolve ->" (insecure-apply-resolve "+" [1 2 3]))
    (catch Exception e (println "insecure-apply-resolve raised:" (.getMessag
