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
