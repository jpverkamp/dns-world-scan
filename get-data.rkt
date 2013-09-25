#lang racket

; Run a sequence of commands with system
(define (for-each/system . cmds)
  (for ([cmd (in-list cmds)])
    (displayln cmd)
    (system cmd)))

; Download the most recent Alexa top million as targets
; Remove the numbers, leaving just hostnames
(for-each/system
 "wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"
 "unzip top-1m.csv.zip"
 "cut -d \",\" -f 2 top-1m.csv > targets.txt"
 "rm top-1m.csv.zip top-1m.csv")

; Download MaxMind's free country level GeoIP database
(for-each/system
 "wget http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip"
 "unzip GeoIPCountryCSV.zip"
 "mv GeoIPCountryWhois.csv ip-mappings.csv"
 "rm GeoIPCountryCSV.zip")

; Remind the user that they have to provide the resolver definitions
(printf "
resolvers.txt cannot be automatically downloaded.
Please make sure that this file exists before running scan.")