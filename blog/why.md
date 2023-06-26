# why

On July 19 2022, this pull was merged:

https://github.com/refraction-networking/utls/pull/95

since then, the `go.mod` is bloated:

~~~
require (
   github.com/andybalholm/brotli v1.0.4
   github.com/klauspost/compress v1.15.15
)
~~~

Initially, I just had the idea to replace the client hello by wrapping
`crypto/tls`. We can capture the default client hello:

~~~go
package main

import (
   "crypto/tls"
   "fmt"
   "net"
   "net/http"
)

type conn struct {
   net.Conn
}

func (c conn) Write(b []byte) (int, error) {
   fmt.Printf("%q\n\n", b)
   return c.Conn.Write(b)
}

func main() {
   req, err := http.NewRequest("GET", "https://mail.google.com", nil)
   if err != nil {
      panic(err)
   }
   dial_conn, err := net.Dial("tcp", "mail.google.com:443")
   if err != nil {
      panic(err)
   }
   tls_conn := tls.Client(
      &conn{Conn: dial_conn}, &tls.Config{ServerName: "mail.google.com"},
   )
   if err := req.Write(tls_conn); err != nil {
      panic(err)
   }
   if err := tls_conn.Close(); err != nil {
      panic(err)
   }
}
~~~

but we get a failure if we try to reuse it:

~~~go
package main

import (
   "bytes"
   "crypto/tls"
   "net"
   "net/http"
)

var go_client_hello = []byte("\x16\x03\x01\x01\x02\x01\x00\x00\xfe\x03\x03\r\xb6\xf6Ⱦ\x8bh\xaa\xb6ʦ]F\x90\xcf\xf7\xfa\x13dt\xf2\xff'\xc5姩\b\x91\x9b#\xbb \xf1\xe5\xdb\xc1u\x818\xc0\x0e\x10M\xc8\xdd-_\xa5\x04\xcd\x17]\xad\x01\b\xab55\x01\xf4\xfe\x1e\x1f\x17\x00&\xc0+\xc0/\xc0,\xc00̨̩\xc0\t\xc0\x13\xc0\n\xc0\x14\x00\x9c\x00\x9d\x00/\x005\xc0\x12\x00\n\x13\x01\x13\x02\x13\x03\x01\x00\x00\x8f\x00\x00\x00\x14\x00\x12\x00\x00\x0fmail.google.com\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\n\x00\n\x00\b\x00\x1d\x00\x17\x00\x18\x00\x19\x00\v\x00\x02\x01\x00\x00\r\x00\x1a\x00\x18\b\x04\x04\x03\b\a\b\x05\b\x06\x04\x01\x05\x01\x06\x01\x05\x03\x06\x03\x02\x01\x02\x03\xff\x01\x00\x01\x00\x00\x12\x00\x00\x00+\x00\x05\x04\x03\x04\x03\x03\x003\x00&\x00$\x00\x1d\x00 \xb4\xfc%\x1a\x13\xb0A!\x9f\x11\x04\xe47^V\x16\xfb\x96A\xa2U\xccq\xd7\xc1\xe8.\x15b?\xf8F")

type conn struct {
   net.Conn
}

func (c conn) Write(b []byte) (int, error) {
   if bytes.HasPrefix(b, []byte{0x16}) {
      return c.Conn.Write(go_client_hello)
   }
   return c.Conn.Write(b)
}

func main() {
   req, err := http.NewRequest("GET", "https://mail.google.com", nil)
   if err != nil {
      panic(err)
   }
   dial_conn, err := net.Dial("tcp", "mail.google.com:443")
   if err != nil {
      panic(err)
   }
   tls_conn := tls.Client(
      &conn{Conn: dial_conn}, &tls.Config{ServerName: "mail.google.com"},
   )
   if err := req.Write(tls_conn); err != nil {
      panic(err) // tls: server did not echo the legacy session ID
   }
   if err := tls_conn.Close(); err != nil {
      panic(err)
   }
}
~~~
