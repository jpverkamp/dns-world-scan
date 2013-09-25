#lang racket

(require bit-struct
         "udp-socket-lib.rkt")

(provide
 current-dns-timeout
 dns-request
 dns-request/async)

; How long to wait for sync requests (default is 5.0 seconds)
; For async requests, callbacks only work for this long
(define current-dns-timeout (make-parameter 5.0))

; Convert keywords to symbols
(define (keyword->symbol key) (string->symbol (keyword->string key)))

; Make a DNS request, block until the first response is received
; If multiple requests are specified only the first to return will be returned
; Timeouts after `current-dns-timeout` seconds
(define dns-request
  (make-keyword-procedure
   (λ (keys vals server)
     ; Values to set in the callback
     (define response '(timeout))
     (define response-semaphore (make-semaphore 0))
     
     ; Make the async request, pass callback setting our values
     (keyword-apply 
      dns-request/async
      keys vals
      (list server
            (λ response-data
              (set! response response-data)
              (semaphore-post response-semaphore))))
     
     ; Wait until we have a response
     (sync/timeout
      (current-dns-timeout)
      [handle-evt
       response-semaphore
       (λ _ response)]))))

; Make an async DNS request
(define dns-request/async
  (make-keyword-procedure
   (λ (keys vals server callback)
     (for ([key (in-list (map keyword->symbol keys))]
           [val (in-list vals)])
       ; Choose a random port and id for this request
       (define local-port (+ 10000 (random 1000)))
       (define request-id (random 65536))
       
       ; Create the request (error on types we don't deal with yet)
       (define request-packet
         (case key
           [(a)
            (dns->bytes
             (build-dns
              #:id request-id
              #:tc 1
              #:qdcount 1
              #:data
              (bytes-append          ; query / question
               (encode-hostname val) ; query is the hostname
               (bytes 0 1)           ; query type  (1 = Type A, host address)
               (bytes 0 1)           ; query class (1 = IN, Internet address)
               )))]
           [else
            (error 'dns-request "unknown dns type: ~a" key)]))
       
       ; Get a socket
       (define socket (get-socket local-port))
       
       ; Enhance the callback to make sure the response is actually DNS
       (define (real-callback remote-host remote-port buffer)
         (define dns-packet
           (with-handlers (#;[exn? (λ (err) #f)])
             (bytes->dns buffer)))
         
         (when (and dns-packet
                    (= (dns-id dns-packet) request-id)
                    (= (dns-qr dns-packet) 1)
                    (= (dns-z dns-packet) 0))
           (callback remote-host key val (parse-dns-response dns-packet))))
       
       ; Listen for that on the UDP response
       (add-socket-listener! local-port real-callback)
       
       ; After the given timeout, remove it again
       (when (current-dns-timeout)
         (thread 
          (thunk 
           (sleep (current-dns-timeout))
           (remove-socket-listener! local-port real-callback))))
       
       ; Send the packet
       (udp-send-to socket server 53 request-packet)))))

; DNS packets
(define-bit-struct dns
  ([id      16]
   [qr      1]  [opcode  4]  [aa      1]  [tc      1]  [rd      1] 
   [ra      1]  [z       3]  [rcode   4]
   [qdcount 16]
   [ancount 16]
   [nscount 16]
   [arcount 16]
   [data    _]))

; Encode a hostname in the way DNS expects
(define (encode-hostname hostname)
  (bytes-append
   (apply
    bytes-append
    (for/list ([part (in-list (string-split hostname "."))])
      (bytes-append
       (bytes (string-length part))
       (string->bytes/latin-1 part))))
   (bytes 0)))

; Read a DNS encoded hostname, return bytes read and the name
(define (decode-hostname buffer [start 0])
  (cond
    ; Pointer based hostname
    [(>= (bytes-ref buffer start) 64)
     (values 2
             (format "pointer: ~x~x"
                     (bytes-ref buffer start)
                     (bytes-ref buffer (+ start 1))))]
    ; Normal hostname
    [else
     (let loop ([i start] [chunks '()])
       (cond
         [(= 0 (bytes-ref buffer i))
          (values
           (+ 1 (length chunks) (apply + (map bytes-length chunks)))
           (string-join (reverse (map bytes->string/utf-8 chunks)) "."))]
         [else
          (define length (bytes-ref buffer i))
          (define chunk (subbytes buffer (+ i 1) (+ i 1 length)))
          (loop (+ i 1 length) (cons chunk chunks))]))]))

; Convert bytes to a number
(define (bytes->number buffer from to)
  (for/fold ([total 0])
            ([i (in-range from to)])
    (+ (bytes-ref buffer i) (* total 256))))

; Parse a DNS response
(define (parse-dns-response packet)
  ; Get the hostname out of the query (which theoretically we sent)
  (define-values (query-length query-hostname)
    (decode-hostname (dns-data packet) 0))
  
  ; Make sure we got a response
  (define rcode (decode-rcode (dns-rcode packet)))
  (define answers (dns-ancount packet))
  
  (cond
    ; Valid response with at least one answer
    [(and (eq? rcode 'no-error) (> answers 0))
     (define data (dns-data packet))
     (let loop ([c 0]
                [i (+ query-length 4)]
                [answers '()])
       (cond
         ; Done, return
         [(or (>= c (dns-ancount packet))
              (>= i (bytes-length data)))
          (cons rcode (reverse answers))]
         ; Add another response
         [else
          (define-values (answer-length answer-hostname) (decode-hostname data i))
          (define answer-type     (bytes->number data (+ i answer-length 0) (+ i answer-length 2)))
          (define answer-class    (bytes->number data (+ i answer-length 2) (+ i answer-length 4)))
          (define answer-ttl      (bytes->number data (+ i answer-length 4) (+ i answer-length 8)))
          (define answer-rdlength (bytes->number data (+ i answer-length 8) (+ i answer-length 10)))
          (define answer-rdata    (subbytes      data (+ i answer-length 10) (+ i answer-length 10 answer-rdlength)))
          
          ; We're only interested in A records
          (cond
            ; Got an a record
            [(= answer-type 1)
             ; Decode the answer IP address
             (define answer-ip (string-join (map number->string (bytes->list answer-rdata)) "."))
             (loop (+ c 1) 
                   (+ i answer-length 10 answer-rdlength)
                   (cons (list 'A answer-class answer-ip) answers))]
            ; Got something else, just record it
            [else
             (loop (+ c 1) 
                   (+ i answer-length 10 answer-rdlength)
                   (cons (list answer-type answer-class answer-rdata)))])]))]
    ; Reponse is not data
    [else
     (list rcode)]))

; Convert a numeric rcode into a more readable value
(define (decode-rcode rcode)
  (case rcode
    [(0) 'no-error]
    [(1) 'format-error]
    [(2) 'server-failure]
    [(3) 'name-error]
    [(4) 'not-implemented]
    [(5) 'refused]
    [else (string->symbol (format "unknown:~a" rcode))]))