package proxy

import (
	// "strings"
	"bytes"
	"testing"
)

func TestHost(t *testing.T) {
	// c := &Cipher{KeyString: "12345678"}
	// c.New()
	// t.Log("Testing host compressing and decompressing")

	// for _, web := range strings.Split(websites, "\n") {
	// 	t.Log(web, EncryptHost(c, web, HOST_HTTP_FORWARD))
	// 	if DecryptHost(c, EncryptHost(c, web, HOST_HTTP_FORWARD), HOST_HTTP_FORWARD) != web {
	// 		t.Error("Host failed", web)
	// 	}
	// }

	// for _, web := range strings.Split(websites, "\n") {
	// 	if DecryptHost(c, EncryptHost(c, web, HOST_HTTP_FORWARD), HOST_HTTP_CONNECT) == web {
	// 		t.Error("Host failed", web)
	// 	}
	// }
}

func TestCipher(t *testing.T) {
	c := &Cipher{KeyString: "12345678"}
	c.New()
	t.Log("Testing Cipher")

	test := func(m byte) {
		s, buf := c.RandomIV(m)
		m2, buf2 := c.ReverseIV(s)
		if m2 != m || !bytes.Equal(buf, buf2) {
			t.Error(buf, buf2, m, m2)
		}
	}

	for i := 0; i < 100; i++ {
		test(byte(c.Rand.Intn(256)))
	}
}

func TestGenWord(t *testing.T) {
	r := &Cipher{KeyString: "12345678"}
	r.New()

	gen := func() *Cipher {
		ret, n := &Cipher{}, r.Rand.Intn(16)+1
		for i := 0; i < n; i++ {
			ret.KeyString += string(byte(r.Rand.Intn(26)) + 'a')
		}
		ret.New()
		return ret
	}

	for i := 0; i < 100000; i++ {
		genWord(gen(), false)
	}
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
1.2.3.4.5.6.com
[127::1]`
