
## 0.2.1 (April, 22, 2022)

  * Fix the chrono RUSTSEC advisory (#17)
  * Replace `chrono` by `time` crate.

## 0.2.0 (July 6, 2021)

  * Strict SPIFFE ID parsing (#8)
  * Method `validate_jwt_token` returns a `JwtSvid` parsed 
    from given token after validating it using then Workload API (#9)

## 0.1.1 (June 18, 2021)
  * Add method `validate_jwt_token` in the WorkloadApiClient (#2).

## 0.1.0 (June 14, 2021)

Initial implementation of the library (#1):
  * Workload API client with one-shot call methods
  * Certificate and PrivateKey types
  * X.509 SVID and bundle types
  * JWT SVID and bundle types
  * TrustDomain and SpiffeId types