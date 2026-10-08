package parity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Browser struct {
	client *http.Client
	base   string
	csrf   string
	page   string
	cookie []*http.Cookie

	mu     sync.Mutex
	bodies [][]byte
}

func ConsumeBootstrap(rawURL string) (*Browser, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("invalid parity bootstrap URL")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	browser := &Browser{
		client: &http.Client{Jar: jar, Timeout: 10 * time.Second},
		base:   parsed.Scheme + "://" + parsed.Host,
	}
	response, err := browser.client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	browser.page = response.Request.URL.String()
	cookieResponse := response
	if response.Request.Response != nil {
		cookieResponse = response.Request.Response
	}
	for _, cookie := range cookieResponse.Cookies() {
		clone := *cookie
		browser.cookie = append(browser.cookie, &clone)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, errors.New("parity bootstrap did not reach the private page")
	}
	browser.record(body)
	match := regexp.MustCompile(`const csrf='([0-9a-f]+)'`).FindSubmatch(body)
	if len(match) != 2 {
		return nil, errors.New("parity page did not expose its same-origin CSRF binding")
	}
	browser.csrf = string(match[1])
	return browser, nil
}

func (b *Browser) BaseURL() string {
	return b.base
}

func (b *Browser) PageURL() string {
	return b.page
}

func (b *Browser) BootstrapCookies() []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookie := range b.cookie {
		clone := *cookie
		cookies = append(cookies, &clone)
	}
	return cookies
}

func (b *Browser) Bodies() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Join(b.bodies, []byte("\n"))
}

func (b *Browser) Form(path string, values url.Values) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodPost, b.base+path, strings.NewReader(values.Encode()))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	request.Header.Set("Origin", b.base)
	request.Header.Set("X-CosmoEdge-CSRF", b.csrf)
	return b.do(request)
}

func (b *Browser) JSON(method, path string, input any) (int, []byte, error) {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, b.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Origin", b.base)
	request.Header.Set("X-CosmoEdge-CSRF", b.csrf)
	return b.do(request)
}

func (b *Browser) Get(path string) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodGet, b.base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	return b.do(request)
}

func (b *Browser) WaitJSON(path string, timeout time.Duration, accept func(map[string]any) bool) (map[string]any, error) {
	deadline := time.Now().Add(timeout)
	var last map[string]any
	for time.Now().Before(deadline) {
		status, raw, err := b.Get(path)
		if err == nil && status == http.StatusOK && json.Unmarshal(raw, &last) == nil && accept(last) {
			return last, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return last, errors.New("parity result did not reach the expected state")
}

func (b *Browser) do(request *http.Request) (int, []byte, error) {
	response, err := b.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return 0, nil, err
	}
	b.record(raw)
	return response.StatusCode, raw, nil
}

func (b *Browser) record(raw []byte) {
	b.mu.Lock()
	b.bodies = append(b.bodies, append([]byte(nil), raw...))
	b.mu.Unlock()
}

func DecodeObject(raw []byte) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	return object, nil
}

func StringField(object map[string]any, path ...string) string {
	current := any(object)
	for _, key := range path {
		mapping, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = mapping[key]
	}
	value, _ := current.(string)
	return value
}

func BoolField(object map[string]any, path ...string) bool {
	current := Field(object, path...)
	value, _ := current.(bool)
	return value
}

func Field(object map[string]any, path ...string) any {
	current := any(object)
	for _, key := range path {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = mapping[key]
	}
	return current
}

func ObjectField(object map[string]any, path ...string) map[string]any {
	value, _ := Field(object, path...).(map[string]any)
	return value
}

func ArrayField(object map[string]any, path ...string) []any {
	value, _ := Field(object, path...).([]any)
	return value
}

func IntField(object map[string]any, path ...string) int {
	value, _ := Field(object, path...).(float64)
	return int(value)
}
