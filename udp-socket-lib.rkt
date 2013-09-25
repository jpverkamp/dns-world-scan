#lang racket

(provide get-socket
         add-socket-listener!
         remove-socket-listener!)

; Sockets that have already been opened
; (hash/c port udp?)
(define sockets (make-hasheq))

; Listeners sorted by port
; (hash/c port (set/c (remote-host remote-port bytes? -> void)))
(define listeners (make-hasheq))

(define (add-socket-listener! port listener)
  (define new-set (set-add (hash-ref listeners port (seteq)) listener))
  (hash-set! listeners port new-set))

(define (remove-socket-listener! port listener)
  (define new-set (set-remove (hash-ref listeners port (seteq)) listener))
  (if (set-empty? new-set)
      (hash-remove! listeners port)
      (hash-set! listeners port new-set)))

; Get the socket associated with a port, reusing sockets if possible
; (port -> void)
(define (get-socket port)
  (unless (hash-has-key? sockets port)
    ; Create the new socket, bind it to the given port
    (define s (udp-open-socket))
    (udp-bind! s #f port #t)
    
    ; Create a listening thread for it
    ; TODO: Allow some way to clean these up?
    ; TODO: Print out any errors we catch rather than ignoring them
    (thread 
     (thunk
      (define b (make-bytes 1024))
      (let loop ()
        (sync 
         [handle-evt 
          (udp-receive!-evt s b)
          (λ (event)
            ; Unpacket the event
            (define-values (bytes-received source-hostname source-port)
              (apply values event))
            
            ; Send the results to any listeners for that port
            ; Hope they can deal with anything else random to this port :)
            (for ([listener (in-set (hash-ref listeners port (set)))])
              (listener source-hostname
                        source-port
                        (subbytes b 0 bytes-received)))
            
            ; Wait for another event
            (loop))]))))
    
    ; Record it
    (hash-set! sockets port s))
    
  ; Return the old socket if we had one, new otherwise
  (hash-ref sockets port))