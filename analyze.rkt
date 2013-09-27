#lang racket

(define data (make-hash))

; Load data
(for ([file (in-vector (current-command-line-arguments))])
  (call-with-input-file "output-1380140581377.txt"
    (λ (fin)
      (let/ec break
        (let loop ()
          (define line (read fin))
          (when (eof-object? line)
            (break))
          
          (match-define (list-rest resolver-ip resolver-country target response-type response) line)
          
          (define by-target (hash-ref! data target (make-hash)))
          (for ([each (in-list response)])
            (match-define (list type class data) each)
            (define by-ip (hash-ref! by-target data (make-hash)))
            (hash-set! by-ip resolver-country (set-add (hash-ref! by-ip resolver-country (set)) resolver-ip)))
          
          (loop))))))

; Count distinct results for each resolver
#;(begin
  (define resolver:ip:count (make-hash))
  (for* ([(target by-target) (in-hash data)]
         [(ip by-ip) (in-hash by-target)]
         [(country resolvers) (in-hash by-ip)]
         [resolver (in-set resolvers)])
    (define key (format "~a (~a)" resolver country))
    (define ip:count (hash-ref! resolver:ip:count key (make-hash)))
    (hash-set! ip:count ip (+ 1 (hash-ref ip:count ip 0)))
    (hash-set! ip:count 'all (+ 1 (hash-ref ip:count 'all 0))))
  
  (for ([(resolver ip:count) (in-hash resolver:ip:count)])
    (printf "~a:\n" resolver)
    (printf "\tall: ~a\n" (hash-ref ip:count 'all 0))
    (for ([(ip count) (in-hash ip:count)]
          #:when (and (not (eq? ip 'all))
                      (> count 5)))
      (printf "\t~a: ~a\n" ip count))
    (printf "\n"))
  
  (exit))

; Count distinct results for each hostname 
#;(begin
  (for ([(target by-target) (in-hash data)]
        #:when (not (and (>= (string-length target) 6)
                         (or (equal? (substring target 0 6) "instag")
                             (equal? (substring target 0 6) "google")
                             (equal? (substring target 0 6) "blogge")
                             (equal? (substring target 0 6) "youtub")))))
    (printf "~a:\n" target)
    (for ([each (sort 
                 (for/list ([(ip by-ip) (in-hash by-target)])
                   (list ip 
                         (hash-count by-ip)
                         (for/set ([(country resolvers) (in-hash by-ip)])
                           country)))
                 (λ (a b)
                   (> (second a) (second b))))]
          #:when (and (not (equal? (first each) "0.0.0.1"))
                      (not (equal? (first each) "1.0.0.1"))
                      (not (equal? (first each) "66.154.126.57"))
                      (not (equal? (first each) "161.64.123.237"))
                      (not (equal? (first each) "161.64.123.240"))
                      (not (equal? (first each) "161.64.123.242"))
                      (not (equal? (first each) "194.14.252.105"))
                      (< (second each) 5)))
      (printf "\t~a = ~a ~a\n" 
              (first each) 
              (second each) 
              (set->list (third each))))
    (printf "\n")))
