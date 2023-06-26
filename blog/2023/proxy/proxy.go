package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

func (s spy_conn) Read(b []byte) (int, error) {
	num, err := s.Conn.Read(b)
	if bytes.Contains(b, []byte("android.googleapis.com")) {
		fmt.Printf("%q\n", b[:num])
	}
	return num, err
}

func main() {
	var s http.Server
	s.Addr = ":8080"
	s.Handler = spy_conn{}
	fmt.Println(s.Addr)
	err := s.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

type spy_conn struct {
	net.Conn
}

func (s spy_conn) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	err := s.serve(rw, req)
	if err != nil {
		fmt.Println(err)
	}
}

func (s spy_conn) serve(rw http.ResponseWriter, req *http.Request) error {
	if req.Method != http.MethodConnect {
		return nil
	}
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		return nil
	}
	target_conn, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		return err
	}
	s.Conn, _, err = hijacker.Hijack()
	if err != nil {
		return err
	}
	buf := []byte("HTTP/1.1 ")
	buf = strconv.AppendInt(buf, http.StatusOK, 10)
	buf = append(buf, "\n\n"...)
	if _, err := s.Write(buf); err != nil {
		return err
	}
	if _, err := io.Copy(target_conn, s); err != nil {
		return err
	}
	if err := s.Close(); err != nil {
		return err
	}
	if err := target_conn.Close(); err != nil {
		return err
	}
	return nil
}
