package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bc_abe/utils/config"
)

type apiResp struct {
	Code    int             `json:"code"`
	Message string          `json:"message,omitempty"`
	Data    json.RawMessage `json:"data"`
}

type userData struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
}

type encryptData struct {
	AssetID string `json:"assetId"`
}

type loadSession struct {
	username, password string
	userID             uint
	assetID            string
	policy             string
	orgName            string
	auth               string
}

type ucClient struct {
	base   string
	client *http.Client
}

func newUCClient(base string) *ucClient {
	return &ucClient{
		base:   strings.TrimRight(base, "/"),
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func (c *ucClient) api(method, path string, body any) (json.RawMessage, float64, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	start := time.Now()
	resp, err := c.client.Do(req)
	ms := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return nil, ms, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ms, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trimBody(raw))
	}
	var wrap apiResp
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, ms, fmt.Errorf("invalid json: %w", err)
	}
	if wrap.Code != 0 {
		msg := wrap.Message
		if msg == "" {
			msg = "api code != 0"
		}
		return nil, ms, fmt.Errorf("%s", msg)
	}
	return wrap.Data, ms, nil
}

func trimBody(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 240 {
		return s[:240] + "..."
	}
	return s
}

func clientPolicy(orgName string) (auth, policy string) {
	auth = config.AuthNameForOrg(orgName)
	policy = fmt.Sprintf("Vitality@%s /\\ locschool@%s", auth, auth)
	return auth, policy
}

// runClientFlow 与 Web 前端一致：注册 → keys/auto → 加密 → 解密。
func runClientFlow(base string) (*loadSession, error) {
	uc := newUCClient(base)
	auth, policy := clientPolicy("org1")
	sess := &loadSession{
		username: fmt.Sprintf("load_%d", time.Now().UnixNano()),
		password: "loadpw",
		orgName:  "org1",
		auth:     auth,
		policy:   policy,
	}

	data, _, err := uc.api(http.MethodPost, "/api/v1/register", map[string]any{
		"username": sess.username, "password": sess.password,
		"orgName": sess.orgName, "attributes": "Vitality,locschool",
	})
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	var user userData
	if err := json.Unmarshal(data, &user); err != nil || user.ID == 0 {
		return nil, fmt.Errorf("register: invalid user id")
	}
	sess.userID = user.ID

	_, _, err = uc.api(http.MethodPost, "/api/v1/keys/auto", map[string]any{
		"userId": sess.userID, "location": "school", "hour": 16, "hourOp": "==",
	})
	if err != nil {
		return nil, fmt.Errorf("keys/auto: %w", err)
	}

	data, _, err = uc.api(http.MethodPost, "/api/v1/files/encrypt", map[string]any{
		"userId": sess.userID, "filename": "demo.txt",
		"content": "load-bench-payload", "policy": policy,
	})
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	var enc encryptData
	if err := json.Unmarshal(data, &enc); err != nil || enc.AssetID == "" {
		return nil, fmt.Errorf("encrypt: missing assetId")
	}
	sess.assetID = enc.AssetID

	_, _, err = uc.api(http.MethodPost, "/api/v1/files/decrypt", map[string]any{
		"userId": sess.userID, "assetId": sess.assetID,
	})
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return sess, nil
}

type loadStats struct {
	total, ok, errors int
	qps, p50, p95, p99 float64
}

func runLoadRound(uc *ucClient, method, path string, bodyFn func(uint) any, workers, total int) (loadStats, string) {
	var okCount, errCount int64
	latencies := make([]float64, 0, total)
	var mu sync.Mutex
	var sampleErr string
	sem := make(chan struct{}, workers)
	startAll := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(seq uint) {
			defer wg.Done()
			defer func() { <-sem }()
			var body any
			if bodyFn != nil {
				body = bodyFn(seq)
			}
			_, elapsed, err := uc.api(method, path, body)
			if err != nil {
				atomic.AddInt64(&errCount, 1)
				mu.Lock()
				if sampleErr == "" {
					sampleErr = err.Error()
				}
				mu.Unlock()
				return
			}
			atomic.AddInt64(&okCount, 1)
			mu.Lock()
			latencies = append(latencies, elapsed)
			mu.Unlock()
		}(uint(i))
	}
	wg.Wait()
	elapsed := time.Since(startAll).Seconds()
	sortFloats(latencies)
	return loadStats{
		total: total, ok: int(okCount), errors: int(errCount),
		qps: float64(total) / elapsed,
		p50: percentile(latencies, 0.50), p95: percentile(latencies, 0.95), p99: percentile(latencies, 0.99),
	}, sampleErr
}

func runLoadTest(outDir, base string, conc, n int) error {
	fmt.Printf("load test: base=%s concurrency=%d per_endpoint=%d\n", base, conc, n)
	fmt.Println("== client flow ==")
	sess, err := runClientFlow(base)
	if err != nil {
		return err
	}
	fmt.Printf("ok user=%s id=%d asset=%s policy=%s\n", sess.username, sess.userID, sess.assetID, sess.policy)

	uc := newUCClient(base)
	eps := []struct {
		name, method, path string
		body             func(uint) any
	}{
		{"register", http.MethodPost, "/api/v1/register", func(i uint) any {
			return map[string]any{
				"username": fmt.Sprintf("load_%d_%d", time.Now().UnixNano(), i),
				"password": "loadpw", "orgName": "org1", "attributes": "Vitality,locschool",
			}
		}},
		{"login", http.MethodPost, "/api/v1/login", func(_ uint) any {
			return map[string]any{"username": sess.username, "password": sess.password}
		}},
		{"keys_auto", http.MethodPost, "/api/v1/keys/auto", func(_ uint) any {
			return map[string]any{"userId": sess.userID, "location": "school", "hour": 16, "hourOp": "=="}
		}},
		{"encrypt", http.MethodPost, "/api/v1/files/encrypt", func(_ uint) any {
			return map[string]any{
				"userId": sess.userID, "filename": "load.txt",
				"content": "payload", "policy": sess.policy,
			}
		}},
		{"decrypt", http.MethodPost, "/api/v1/files/decrypt", func(_ uint) any {
			return map[string]any{"userId": sess.userID, "assetId": sess.assetID}
		}},
		{"list_files", http.MethodGet, fmt.Sprintf("/api/v1/files?userId=%d", sess.userID), nil},
		{"list_keys", http.MethodGet, fmt.Sprintf("/api/v1/keys?userId=%d", sess.userID), nil},
	}

	w, err := newCSV(outDir, "load_test.csv", []string{"endpoint", "total", "ok", "errors", "error_rate", "qps", "p50_ms", "p95_ms", "p99_ms", "note"})
	if err != nil {
		return err
	}
	defer w.close()

	fmt.Printf("%-12s %8s %8s %8s %10s %8s %8s %8s %8s\n",
		"endpoint", "total", "ok", "errors", "err_rate", "qps", "p50_ms", "p95_ms", "p99_ms")
	for _, ep := range eps {
		st, sampleErr := runLoadRound(uc, ep.method, ep.path, ep.body, conc, n)
		note := sampleErr
		er := 0.0
		if st.total > 0 {
			er = float64(st.errors) / float64(st.total)
		}
		w.row(ep.name, fmt.Sprint(st.total), fmt.Sprint(st.ok), fmt.Sprint(st.errors),
			fmt.Sprintf("%.2f", er), fmt.Sprintf("%.2f", st.qps),
			fmt.Sprintf("%.2f", st.p50), fmt.Sprintf("%.2f", st.p95), fmt.Sprintf("%.2f", st.p99), note)
		fmt.Printf("%-12s %8d %8d %8d %9.2f%% %8.2f %8.2f %8.2f %8.2f",
			ep.name, st.total, st.ok, st.errors, er*100, st.qps, st.p50, st.p95, st.p99)
		if sampleErr != "" {
			fmt.Printf("  err: %s", sampleErr)
		}
		fmt.Println()
	}
	fmt.Println("load CSV ->", fmt.Sprintf("%s/load_test.csv", outDir))
	return nil
}
