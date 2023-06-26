# Proxy

To capture Android TLS handshake, start the server, and go to Android Emulator
Extended Controls. Choose Manual proxy configuration, then enter:

~~~
127.0.0.1:8080
~~~

and click Apply. Then wait about one minute and the hello should be captured.

- https://android.stackexchange.com/questions/243184/capture-tls-handshake
- https://github.com/spritesprite/proxychannel
- https://unix.stackexchange.com/questions/208412/how-to-see-list-of-curl
