package shoco

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func randomString() string {
	ret := ""
	_rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	ln := _rand.Intn(64) + 64

	for i := 0; i < ln; i++ {
		ret += string(32 + byte(_rand.Intn(90)))
	}

	return ret
}

func TestShoco(t *testing.T) {
	t.Log("Testing shoco compressing and decompressing")

	for i := 0; i < 65536; i++ {
		v := randomString()
		if v != Decompress(Compress(v)) {
			t.Error("Shoco failed", v)
		}
	}
}

func TestHost(t *testing.T) {
	t.Log("Testing shoco host compressing and decompressing")

	for _, web := range strings.Split(websites, "\n") {
		if DecompressHost(CompressHost(web)) != web {
			t.Error("ShocoHost failed", web)
		}
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
porn555.com`
