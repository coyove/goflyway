package proxy

import (
	"../config"
	"encoding/base32"
	"strings"
	"testing"
)

func TestHost(t *testing.T) {
	config.LoadConfig()
	t.Log("Testing shoco host compressing and decompressing")

	for _, web := range strings.Split(websites, "\n") {
		t.Log(web, EncryptHost(web, HOST_HTTP_FORWARD))
		if DecryptHost(EncryptHost(web, HOST_HTTP_FORWARD), HOST_HTTP_FORWARD) != web {
			t.Error("ShocoHost failed", web)
		}
	}

	for _, web := range strings.Split(websites, "\n") {
		if DecryptHost(EncryptHost(web, HOST_HTTP_FORWARD), HOST_HTTP_CONNECT) == web {
			t.Error("ShocoHost failed", web, EncryptHost(web, HOST_HTTP_FORWARD))
		}
	}
}

func TestBase32AnsBase32(t *testing.T) {
	config.LoadConfig()
	t.Log("Testing Base32 and base32")

	r := NewRand()

	gen := func(length int) []byte {
		buf := make([]byte, length)
		for i := 0; i < length; i++ {
			buf[i] = byte(r.Intn(256))
		}
		return buf
	}

	_base32 := func(in []byte) string {
		str := base32.NewEncoding("0123456789abcdfgijklmnopqsuvwxyz").EncodeToString(in)
		str = strings.Replace(str, "======", "t", -1)
		str = strings.Replace(str, "=====", "h", -1)
		str = strings.Replace(str, "====", "e", -1)
		str = strings.Replace(str, "===", "r", -1)
		str = strings.Replace(str, "==", "th", -1)
		str = strings.Replace(str, "=", "er", -1)
		return str
	}

	const COUNT = 100000
	test := func(length int) {
		b32, b35 := 0, 0
		for i := 0; i < COUNT; i++ {
			buf := gen(length)
			b32 += len(_base32(buf))
			b35 += len(Base32Encode(buf))
		}

		t.Log(length, float64(b32)/float64(b35))
	}

	for i := 1; i <= 8; i++ {
		test(i)
	}
	b := gen(9)
	t.Log(_base32(b), Base32Encode(b))
}

const websites = `google.com
youtube.com
facebook.com
baidu.com
wikipedia.org
yahoo.com
google.co.in
reddit.com
qq.com
amazon.com
taobao.com
google.co.jp
twitter.com
tmall.com
vk.com
live.com
instagram.com
sohu.com
sina.com.cn
weibo.com
jd.com
360.cn
google.de
google.co.uk
google.fr
google.ru
linkedin.com
google.com.br
list.tmall.com
google.com.hk
yandex.ru
netflix.com
google.it
yahoo.co.jp
google.es
t.co
ebay.com
pornhub.com
imgur.com
google.ca
alipay.com
twitch.tv
google.com.mx
bing.com
xvideos.com
youth.cn
msn.com
tumblr.com
ok.ru
aliexpress.com
microsoft.com
mail.ru
gmw.cn
stackoverflow.com
wordpress.com
onclkds.com
hao123.com
github.com
imdb.com
csdn.net
amazon.co.jp
livejasmin.com
blogspot.com
wikia.com
google.com.au
office.com
apple.com
pinterest.com
microsoftonline.com
paypal.com
google.com.tw
xhamster.com
whatsapp.com
google.com.tr
google.co.id
google.pl
popads.net
detail.tmall.com
nicovideo.jp
bongacams.com
diply.com
adobe.com
google.com.ar
coccoc.com
thepiratebay.org
amazon.de
txxx.com
craigslist.org
googleusercontent.com
amazon.in
dropbox.com
booking.com
tianya.cn
so.com
google.com.ua
xnxx.com
pixnet.net
google.com.pk
uptodown.com
porn555.com
doamin.google
wiki
com
1.2.3.4
1.2.3.4.5.6.com`
