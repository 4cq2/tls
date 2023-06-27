# how

Implement FingerprintClientHello to generate ClientHelloSpec from ClientHello
raw bytes:

https://github.com/refraction-networking/utls/commit/2179f286

before the first commit, lets remove large items:

~~~
handshake_client_test.go
handshake_server_test.go
testdata
~~~

now create `go.mod`:

~~~
go mod init 2a.pages.dev/tls
~~~

create `go.sum`:

~~~
go mod tidy
~~~

remove:

~~~
.travis.yml
CONTRIBUTING.md
CONTRIBUTORS_GUIDE.md
auth_test.go
conn_test.go
cpu
example_test.go
examples
generate_cert.go
handshake_messages_test.go
handshake_test.go
key_schedule_test.go
logo.png
logo_small.png
prf_test.go
testenv
tls_test.go
u_common_test.go
u_conn_test.go
u_fingerprinter_test.go
~~~

then:

~~~diff
+++ b/common.go
@@ -21,2 +20,0 @@ import (
-
-       "github.com/refraction-networking/utls/cpu"
~~~

error:

~~~
common.go:923:20: undefined: cpu
~~~

fix:

~~~diff
+++ b/common.go
@@ -1097,46 +1097,14 @@ func initDefaultCipherSuites() {
-       var topCipherSuites []uint16
-
-       // Check the cpu flags for each platform that has optimized GCM implementations.
-       // Worst case, these variables will just all be false.
-       var (
-               hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
-               hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
-               // Keep in sync with crypto/aes/cipher_s390x.go.
-               // hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)
-               hasGCMAsmS390X = false // [UTLS: couldn't be bothered to make it work, we won't use it]
-
-               hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
-       )
-
-       if hasGCMAsm {
-               // If AES-GCM hardware is provided then prioritise AES-GCM
-               // cipher suites.
-               topCipherSuites = []uint16{
-                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
-               }
-               varDefaultCipherSuitesTLS13 = []uint16{
-                       TLS_AES_128_GCM_SHA256,
-                       TLS_CHACHA20_POLY1305_SHA256,
-                       TLS_AES_256_GCM_SHA384,
-               }
-       } else {
-               // Without AES-GCM hardware, we put the ChaCha20-Poly1305
-               // cipher suites first.
-               topCipherSuites = []uint16{
-                       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
-                       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
-                       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
-                       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
-               }
-               varDefaultCipherSuitesTLS13 = []uint16{
-                       TLS_CHACHA20_POLY1305_SHA256,
-                       TLS_AES_128_GCM_SHA256,
-                       TLS_AES_256_GCM_SHA384,
-               }
+       // Without AES-GCM hardware, we put the ChaCha20-Poly1305
+       // cipher suites first.
+       topCipherSuites := []uint16{
+               TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
+               TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
+               TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
+               TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
+               TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
+               TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
+       }
+       varDefaultCipherSuitesTLS13 = []uint16{
+               TLS_CHACHA20_POLY1305_SHA256,
+               TLS_AES_128_GCM_SHA256,
+               TLS_AES_256_GCM_SHA384,
~~~
