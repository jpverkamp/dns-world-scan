#lang racket

(require "dns-lib.rkt")

(define currently-debugging (make-parameter #t))
(define debug
  (let ([s (make-semaphore 1)])
    (λ (fmt . args)
      (call-with-semaphore 
       s
       (thunk              
        (when (currently-debugging)
          (apply printf (cons (string-append "DEBUG: " fmt "\n") args))))))))

; ----- ----- ----- ----- ----- 
; 0) Get command line parameters

(define alexa-top-n (make-parameter 100))
(define resolvers/country (make-parameter 5))
(define timeout (make-parameter 5.0))

(command-line
 #:program "scan.rkt"
 #:once-each
 [("-n" "--alexa-top-n")
  n
  "Scan the top n Alexa ranked sites (default = 100)"
  (alexa-top-n (string->number n))]
 [("-r" "--resolvers")
  r
  "The maximum number of resolvers to use per country (default = 5)"
  (resolvers/country (string->number r))]
 [("-t" "--timeout")
  t
  "Timeout for DNS requests (default = 5.0 seconds)"
  (timeout (string->number t))])

; ----- ----- ----- ----- ----- 
; 1) Load data

(unless (and (file-exists? "targets.txt")
             (file-exists? "resolvers.txt")
             (file-exists? "ip-mappings.csv"))
  (for-each displayln
            '("Error: Data file(s) not found. Please ensure that the following files exist:"
              "- targets.txt - a list of hostnames (one per line) to scan"
              "- resolvers.txt - a list of open DNS resolvers (one per line) to scan with"
              "- ip-mappings.csv - a list of IP -> country mappings (numeric-ip-from, numeric-ip-to, ip-from, ip-to, country)"))
  (exit))

; 1a) Load list of targets (dynamically?) (Alexa Top n)
(debug "Loading list of targets, keeping top ~a" (alexa-top-n))
(define targets
  (call-with-input-file "targets.txt"
    (λ (fin)
      (for/list ([i (in-range (alexa-top-n))]
                 [line (in-lines fin)])
        line))))

; 1b) Load list of resolvers (from Drew)
(debug "Loading resolvers")
(define resolvers (file->lines "resolvers.txt"))

; 1c) Load list of IP/country mappings (dynamically?) (GeoMind Lite)
; format is csv: ip-from, ip-to, numeric-from, numeric-to, code, country
; Lookup using a binary search
(debug "Loading IP -> country database")
(define (ip->number ip)
  (for/fold ([total 0])
    ([byte (in-list (map string->number (string-split ip ".")))])
    (+ byte (* total 256))))

(define (number->ip ip)
  (let loop ([i ip] [ls '()])
    (cond
      [(= i 0) (string-join (map number->string ls) ".")]
      [else    (loop (quotient i 256) (cons (remainder i 256) ls))])))

(define ip->country
  (let ([data 
         (list->vector
          (sort
           (for/list ([line (in-list (file->lines "ip-mappings.csv"))])
             (match-define (list-rest _ _ ip-from ip-to cc country)
               (string-split line ","))
             (list (string->number (string-trim ip-from "\""))
                   (string->number (string-trim ip-to "\""))
                   (string-trim 
                    (string-join 
                     (reverse (map (λ (x) (string-trim x "\"")) country)) " "))))
           (λ (a b)
             (< (first a) (first b)))))])
    (λ (ip)
      (cond
        [(string? ip) (ip->country (ip->number ip))]
        [else
         (let loop ([lo 0] [hi (vector-length data)])
           (define mid (quotient (+ lo hi) 2))
           (match-define (list ip-from ip-to country) (vector-ref data mid))
           (cond
             [(<= ip-from ip ip-to) country]
             [(or (= lo mid) 
                  (= mid hi))       #f]
             [(< ip ip-from)        (loop lo mid)]
             [(> ip ip-to)          (loop mid hi)]
             [else                  (error 'ip->country "unknown ip ~a" ip)]))]))))

; ----- ----- ----- ----- ----- 
; 2) Find a small set of resolvers per country

; 2a) Split the list of resolvers by country
(debug "Reorganizing resolvers by country")
(define resolvers-by-country (make-hash))
(for ([ip (in-list resolvers)])
  (with-handlers ([exn? (λ _ (printf "skipping ~a\n" ip))])
    (define country (ip->country ip))
    (when country
      (define new-set (set-add (hash-ref! resolvers-by-country country (set)) ip))
      (hash-set! resolvers-by-country country new-set))))

; 2b) Query random IPs in each country
; 2b-i)  If it returns a valid response, add it to the list
;        Remove any other IPs within the same /n prefix (avoid same ISPs etc)
; 2b-ii) If it doesn't, try the next IP in that country
; 2c) If we have n resolvers for a country, stop looking; if not, go to 2a for them
(debug "Narrowing resolver list to ~a per country" (resolvers/country))
(let ([threads-finished 0])
  (for-each
   thread-wait
   (for/list ([(country ips) (in-hash resolvers-by-country)])
     (thread
      (thunk
       (parameterize ([current-dns-timeout (timeout)])
         (let loop ([ips (shuffle (set->list ips))]
                    [active '()])
           (cond
             ; No more IPs to scan or found enough
             [(or (null? ips)
                  (>= (length active) (resolvers/country)))
              (set! threads-finished (+ threads-finished 1))
              (debug "~a/~a: ~a is ~a (~a active) -- ~a" threads-finished (hash-count resolvers-by-country) country (if (>= (length active) (resolvers/country)) "out" "full") (length active) active)
              (hash-set! resolvers-by-country country active)]
             ; Got a response, check for no-error and record
             ; TODO: remove matching prefixes
             [(dns-request (first ips) #:a "www.google.com")
              => (λ (response)
                   (match-define (list who what where result) response)
                   (cond
                     [(and (eq? (first result) 'no-error)
                           (not (null? (rest result))))
                      (loop (rest ips) (cons (first ips) active))]
                     [else
                      (loop (rest ips) active)]))]
             ; Response timed out
             [else
              (loop (rest ips) active)]))))))))

; ----- ----- ----- ----- ----- 
; 3) Query targets on each resolver
;    Group by target, for Alexa Top 100 and 5 resolvers/country:
;      100 requests/resolver
;      1000 requests/pass

(define output-filename (format "output-~a.txt" (current-milliseconds)))
(debug "Running queries (output to ~a):" output-filename)

(call-with-output-file output-filename
  (λ (fout)
    (define s (make-semaphore 1))
    (parameterize ([current-dns-timeout (timeout)])
      (for ([i (in-naturals 1)]
            [target (in-list targets)])
        (debug "\tScanning ~a/~a: ~a" i (alexa-top-n) target)
        (for* ([(country ips) (in-hash resolvers-by-country)]
               [ip (in-list ips)])
          (dns-request/async 
           ip #:a target
           (λ (host type query response)
             (define result (list* host country query response))
             (call-with-semaphore 
              s
              (thunk
               (write result fout)
               (newline fout)
               (flush-output fout))))))
        (sleep (+ 1.0 (timeout)))))))