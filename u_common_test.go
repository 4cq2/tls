package tls

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

func Test_Android(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	u, err := user(home + "/gmail.json")
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{
		"Email":              {u["username"]},
		"Passwd":             {u["password"]},
		"client_sig":         {""},
		"droidguard_results": {"-"},
	}.Encode()
	req, err := http.NewRequest(
		"POST", "https://android.googleapis.com/auth",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tr := Transport{Spec: Android_API_26}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(res.Body); err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tr._Conn._Conn._Close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println(res.Status)
}

func user(name string) (map[string]string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func Test_Builder(t *testing.T) {
	{
		b := builder("hello")
		b._Add_String("world")
		b._Add_Bytes([]byte("hello"))
		fmt.Printf("%q\n", b)
	}
	{
		b := builder("hello")
		b.add_uint8_prefixed(func(b *builder) {
			b.add_uint8(0x0a)
		})
		fmt.Printf("%q\n", b)
	}
	{
		b := builder("hello")
		b.add_uint16_prefixed(func(b *builder) {
			b.add_uint16(0x0a0b)
		})
		fmt.Printf("%q\n", b)
	}
	{
		b := builder("hello")
		b.add_uint24_prefixed(func(b *builder) {
			b.add_uint24(0x0a0b0c0d)
		})
		fmt.Printf("%q\n", b)
	}
	{
		b := builder("hello")
		b.add_uint32_prefixed(func(b *builder) {
			b.add_uint32(0x0a0b0c0d)
		})
		fmt.Printf("%q\n", b)
	}
	{
		b := builder("hello")
		b._Add_Uint64(0x0a0b0c0d)
		fmt.Printf("%q\n", b)
	}
}

func Test_Fingerprint(t *testing.T) {
	hello := []byte(Android_Hellos[0])
	spec, err := new(_Fingerprinter)._FingerprintClientHello(hello)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%+v\n", spec)
}

var Android_Hellos = []string{
	// Android API 21:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03A\xbee\xe3\xfdL\xa7f\xbf\xab\xecI\x9cO\xc1\xdfRc\xec\xce\x7f\x96\aWZ\x03\x0f\xc2g\xc1\xdd\xd9 \x9b$\xa3e\xe2m\xcbLn\x00\x89\x9e\x99\x94Կ\x86\xd6)\xd7\xe1:\xb5\xa3\x8f\xfe\x82Jه\xbb\x16\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \xf5\xd5yl\xf0\x01\xd9\xd1G\xba|\x1c\xc2\x11\x8e\x0e\xd8\nEO\x83=\xe56\xfe\xe0yG6\xbcb.\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 22:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03i-\xc6Q\xcdFOx\xfc\xf6\xccn\x1a2\x9f\x9ar|\x8bU\x9a\xe0މ\x13s\x9a\xc6Y\xaa\xae\xc0 \xc8\x02eHS\x90Gv\x1fEf\xcc\xe5}\x98\x85\x18\x80z\x1e\xda\xd5\xe9H\x00b0I\xabd\xa1d\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \xe5#k\xa3\xf2\xd9Aj\xf0~\xe0l\x10:4\xcba\xfe\x8aa\xea\xab^\v0Ej+\x8c\x85\x85n\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 23:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03y\xc3\xd9\xe0\xb4?b\xc3L\x1fR\xb4]\x1c]c\xfc\xba\xcel\xf4\xf7\xb27(硣\x84\x84V\xa4 \xc6\x12\xe8g{\x01\x9d\xfd\x1d\xb7\xb5\x9d\xff\x85\xd2_\xac\xedW\xa5S^\xc80\x0f\xa0\xe0\x8e3pd\x06\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \x8b\x19\xf1d{z>\xd9\xc0\xaf\x9f2\xa7{\xe6WG1\xb1\xe4\x81\x15\xc3\xe0(\x04H\xc92\xea\x81\x15\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 24:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x89\x0f\x92/<\xf9\xb1\xcc#6\xc7q~\xd5\xdc\"\x19\x14\x1e\x89\b\xf7\x97)(\x19\a\xecU\x8b6\xb3 g\xf9ZS\x9f%\xfdU\xa7\xe5'\xa8\xc2f\nfNPg\xe0\xd8{\xd33'zc\x0f(̀O\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \xf9Z軘#\xfa\xc1\x11\x88Q\xb5\x00\xd5W\x8b\xb7=\x1eϾⶺ\x1b4>\"\xe3=\xc7\b\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 25:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x0f=]\x1b\xe0O\xdf\xf0Bֽ\f\xbf)\x926\x89\xc9`\xdbo\xa3\x91V?\xa6mn%\xb7\x0e\xdb \xb7\xfbiA\xe2'ף\xff\xcf/\x87\xe73\xac\xbf\xee\xe6\xf4\x80*\xa1\xc5.\xe7'\xfd\xf2\x9be\xab\xc2\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \xaf\xa2\x01!\xa5\xeab\xd5绕\xa0\xa8u|\xcd\xe6\xc5{Ņ\xc8\x00\x00\x84\xdfz짺--\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 26:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x1e{\xb75\x1f\xfdi\xcd\xf8\x86\xe4\xeb\f\xe7~5&J\xe8\xd9\xf1\x06 r\x85\x84Mzt\xf5\x87\xee \xa5\xc3x\xa1\xfd}z\x16\xfc>j8cA\xd7\xe7\xadR\x8e\xc9,L{e\x99\xf4\x054Q\xecf\b\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \x86_Kו\v\x17*\xb0\xd0F҃\x00i\xa4\xd3\xeb\xa4;\x83\xa7k\x1c-se;8#\x12O\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 27:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xe7\x96 f\xad®\x87N\x03XZ]\xe3\xa5\x1c`4\"\xa2ۮr>\x05\xaf*9tx\xfb\x9d ԩ\x81\x8b\x96\x14t\x95$\x00\xf5l߬VK\x93O]!,\x13\xc2;\xf0\t\xb1\xc1pN\x14\xd5\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 mj\x15ZP\xa3\x82\x95\x9a^\x82\xb2w}a\x93})\x1fj\xbao\xc8\\\xc2M\xf4\x9a{\xee)\x06\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 28:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xa2\x7f\x8cM\xe3\x87::H\xa8\"\xf7Ԉ\f\x03\x96\x13\xa9\xf8\xad\xf6\x8f#\x11d\xb0\x9dU\x05js \xeb\x17\x81M\x8fyE\xb9\xf2\xa3\xe1vj\xb6 RW\xb4\x11\n\x00?\xde_\x10^2\xdcӈ(Q\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 6\xbd'\x7f\xcf.\x92P\x18\xef\xb7p\x12^y\xa3\x99\x03va\xbe\xa7$\x92݇\xed9\xceU{\n\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 29:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xe9\xdc\xe7y\xb8\x90d\x83\xa4\xad\xb7\xb4bD\xaef\x17:\xbe\xba\x7f\xa06\xadl\xb6\xd1\xc1\x9dܢ\x17 B2h8X\xb0Jjѧ\x04f\x16Y\x05\x98\xf6\xc1;Az\x1d\x13\xc9~\xcc\x1c0H{`\xec\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \xdei\xd5,\x80\x87\xfcs(\x93\x8d\xc9zE?\r\x18\xabn\f\xd4FŹ\xfbԈ\xb9\x1a\xd1<&\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 30:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03یw\x8e\xeeO\"\x18쳶G\x99`\xb5!\x84k\x1ba\x1b1L\xa5J/\xdbp\xbf\xd63g ?\xc4ק\xb5\xa9\xc2qY\xb9\x96H\xfb\v\xe9\xab\xcf\x1b\x87v\xddR\xc3\xe2\x15\xe9\x90@\xf2EB\xbc\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 Y\xae\xeb\x14\xf3MiG$*\xb2\x84\xb8\xeb\x81\xe8\xef\xf3{<\x05\x18y\x1bF\xb0\x82\xc2v\\K\x13\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 31:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03P\x87\x006\xfe]\xaf\xed2\xa9\xdd\x11E\xeb\xca\x14B\xe9d\x16\xe5K\xe66e\xbaTQ\xfb\xf7\xd7\xd5 |\x1e?UҖ(\x1f\x85\x1f\x81\xa4(\xbf\x97\f\rS\x160;\xcf\a\xaa\"\x1b\xfa\xdb\x15\xe1\xb6\xf1\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 \xe9d\xb2\x12{\x8eA\x97\xfb\x8e\xc1R\xfb\xf7\xe3\xce\x1e0\xe8t\x92\x1f\xca \xd3BvnjK\aV\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 32:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xc4\x1em͛%=L\x81,\x91VA\xa5xK\x0f.\xac\x1cڦ;P\x0fr\xc3@\xa9V:\xe9 L\xd8㼑\xa0\x8f\xdf\t\x91N\xe0\xf3\xec\xc3\r7\x97\xcd\x03\xa4{f}l\xd0F\x86\x87v+\xe7\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ۙ\x96\xe7pb\xa8\xd9<8\\\xa5A\x0f\x8dx'\x86\xd9\xd6\xf8X(\xda\x038\x16EUH49\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	// Android API 33:
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xdfں\xa5\xa1\xd1cE\xd4z\xf9\x03\xc13\xfc/\xfc\xadb\x99\v\x8b0\xd6ґ\xbc\x90*\x12\x96\xe5 \xfe|\xe8H\x81\xb3\xf6\x1e\x17\xef\x1c\xae\xad\xcd+\xf1\xe9\xd0p\x16Aϗ\xb9\x14\xd4\xdd\xd0<\xdaT5\x00\"\x13\x01\x13\x02\x13\x03\xc0+\xc0,̩\xc0/\xc00̨\xc0\t\xc0\n\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00/\x005\x01\x00\x01\x91\x00\x00\x00\x1b\x00\x19\x00\x00\x16android.googleapis.com\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\n\x00\b\x00\x06\x00\x1d\x00\x17\x00\x18\x00\v\x00\x02\x01\x00\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\r\x00\x14\x00\x12\x04\x03\b\x04\x04\x01\x05\x03\b\x05\x05\x01\b\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 6\xbd\x1cGh\xf7\xc6\xc9ݖ\xa4\x9d\x16\xe9k`\xfb\x80\xaf\x90r\x05\xda\xe3Z\xc6\xd0t\x8a~\xff5\x00-\x00\x02\x01\x01\x00+\x00\t\b\x03\x04\x03\x03\x03\x02\x03\x01\x00\x15\x00\xf5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

func Test_Sanity(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	u, err := user(home + "/gmail.json")
	if err != nil {
		t.Fatal(err)
	}
	body := url.Values{
		"Email":              {u["username"]},
		"Passwd":             {u["password"]},
		"client_sig":         {""},
		"droidguard_results": {"-"},
	}.Encode()
	req, err := http.NewRequest(
		"POST", "https://android.googleapis.com/auth",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := new(http.Transport).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(res.Body); err != nil {
		t.Fatal(err)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatal(err)
	}
	fmt.Println(res.Status)
}

func Test_String(t *testing.T) {
	fmt.Printf("%#v\n", Android_API_26)
}
