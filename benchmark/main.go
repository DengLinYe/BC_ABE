package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	abeengine "bc_abe/abe"
	"bc_abe/utils/config"
	"bc_abe/utils/gateway"
	"bc_abe/utils/logger"
	gofeabe "github.com/fentec-project/gofe/abe"
)


type bcabeSetup struct {
	engine   *abeengine.Engine
	policy   string
	authpubs *abeengine.AuthPubs
	userattrs *abeengine.UserAttrs
}

func newBCABESetup(policy string, attrs []string) (*bcabeSetup, error) {
	e := abeengine.NewEngine(benchSeed)
	if err := e.InitOrg(); err != nil {
		return nil, err
	}
	if err := e.InitAuthority(); err != nil {
		return nil, err
	}
	policy = abeengine.NormalizePolicySyntax(policy)
	authpubs := e.AuthPubsOfPolicy(policy)
	e.FillAuthPub(authpubs, "auth1")
	var merged *abeengine.UserAttrs
	for _, attr := range attrs {
		ua, err := e.IssueUserKey("bench", attr)
		if err != nil {
			return nil, err
		}
		merged = e.MergeUserKeys(merged, ua)
	}
	if merged != nil {
		for a := range merged.Userkey {
			merged.Coeff[a] = []int{}
		}
	}
	return &bcabeSetup{engine: e, policy: policy, authpubs: authpubs, userattrs: merged}, nil
}

func runBCABEFlows(outDir string) error {
	w, err := newCSV(outDir, "bcabe_four_flows.csv", []string{
		"phase", "step", "duration_ms", "size_bytes", "note",
	})
	if err != nil {
		return err
	}
	defer w.close()

	e := abeengine.NewEngine(benchSeed)

	start := time.Now()
	if err := e.InitOrg(); err != nil {
		return err
	}
	w.row("init", "InitOrg", msSince(start), "", "")

	start = time.Now()
	if err := e.InitAuthority(); err != nil {
		return err
	}
	w.row("init", "InitAuthority", msSince(start), "", "")

	orgLen := len(e.OrgJSON())
	authPubLen := len(e.AuthPubJSON())
	authPrvLen := len(e.AuthPrvJSON())
	curveLen := len(e.CurveJSON())
	w.row("init", "OrgJSON_bytes", "", fmt.Sprint(orgLen), "")
	w.row("init", "AuthPubJSON_bytes", "", fmt.Sprint(authPubLen), "")
	w.row("init", "AuthPrvJSON_bytes", "", fmt.Sprint(authPrvLen), "")
	w.row("init", "CurveJSON_bytes", "", fmt.Sprint(curveLen), "")

	policy := abeengine.NormalizePolicySyntax(defaultPolicy)
	authpubs := e.AuthPubsOfPolicy(policy)
	e.FillAuthPub(authpubs, "auth1")

	secret, err := e.NewSecret()
	if err != nil {
		return err
	}
	content := make([]byte, 1024)
	for i := range content {
		content[i] = byte(i % 256)
	}

	start = time.Now()
	symKey, err := abeengine.SymKeyFromSecret(secret)
	if err != nil {
		return err
	}
	w.row("encrypt", "SymKeyFromSecret", msSince(start), "32", "SHA256(GT)")

	start = time.Now()
	encContent, err := aesEncrypt(symKey, content)
	if err != nil {
		return err
	}
	w.row("encrypt", "AES-GCM", msSince(start), fmt.Sprint(len(encContent)), "1KB content")

	start = time.Now()
	ct, err := e.Encrypt(secret, policy, authpubs)
	if err != nil {
		return err
	}
	ctJSON := abeengine.SerializeCiphertext(ct)
	w.row("encrypt", "ABE.Encrypt", msSince(start), fmt.Sprint(len(ctJSON)), policy)

	var merged *abeengine.UserAttrs
	for _, attr := range defaultAttrs {
		start = time.Now()
		ua, err := e.IssueUserKey("bench", attr)
		if err != nil {
			return err
		}
		w.row("keygen", "IssueUserKey_"+attr, msSince(start), "", "")
		merged = e.MergeUserKeys(merged, ua)
	}
	for a := range merged.Userkey {
		merged.Coeff[a] = []int{}
	}
	uaJSON := abeengine.SerializeUserAttrs(merged)
	w.row("keygen", "UserABEKeyJSON_bytes", "", fmt.Sprint(len(uaJSON)), "")

	start = time.Now()
	gotSecret, err := e.Decrypt(ct, merged)
	if err != nil {
		return err
	}
	w.row("decrypt", "ABE.Decrypt", msSince(start), "", "")

	start = time.Now()
	gotKey, err := abeengine.SymKeyFromSecret(gotSecret)
	if err != nil {
		return err
	}
	plain, err := aesDecrypt(gotKey, encContent)
	if err != nil {
		return err
	}
	w.row("decrypt", "AES-GCM", msSince(start), fmt.Sprint(len(plain)), "")

	w.row("note", "hybrid", "", "", "secret(GT)->SHA256->AES-256-GCM; ABE encrypts GT only")
	return nil
}

func runBCABEVarLen(outDir string) error {
	w, err := newCSV(outDir, "bcabe_varlen.csv", []string{
		"content_bytes", "abe_encrypt_ms", "abe_decrypt_ms", "aes_encrypt_ms", "aes_decrypt_ms", "abe_ct_bytes", "aes_ct_bytes",
	})
	if err != nil {
		return err
	}
	defer w.close()

	setup, err := newBCABESetup(defaultPolicy, defaultAttrs)
	if err != nil {
		return err
	}
	sizes := []int{512, 1024, 4096, 16384, 65536}
	for _, size := range sizes {
		content := make([]byte, size)
		for i := range content {
			content[i] = byte(i % 256)
		}
		secret, _ := setup.engine.NewSecret()
		symKey, _ := abeengine.SymKeyFromSecret(secret)

		start := time.Now()
		ct, err := setup.engine.Encrypt(secret, setup.policy, setup.authpubs)
		if err != nil {
			return err
		}
		abeEncMs := msSince(start)
		ctLen := len(abeengine.SerializeCiphertext(ct))

		start = time.Now()
		encContent, err := aesEncrypt(symKey, content)
		if err != nil {
			return err
		}
		aesEncMs := msSince(start)

		start = time.Now()
		_, err = setup.engine.Decrypt(ct, setup.userattrs)
		if err != nil {
			return err
		}
		abeDecMs := msSince(start)

		gotSecret, _ := setup.engine.Decrypt(ct, setup.userattrs)
		gotKey, _ := abeengine.SymKeyFromSecret(gotSecret)
		start = time.Now()
		_, err = aesDecrypt(gotKey, encContent)
		if err != nil {
			return err
		}
		aesDecMs := msSince(start)

		w.row(fmt.Sprint(size), abeEncMs, abeDecMs, aesEncMs, aesDecMs, fmt.Sprint(ctLen), fmt.Sprint(len(encContent)))
	}
	return nil
}

func runBCABEDepth(outDir string) error {
	w, err := newCSV(outDir, "bcabe_policy_depth.csv", []string{
		"attr_count", "policy", "abe_encrypt_ms", "abe_decrypt_ms", "ct_bytes", "user_key_bytes",
	})
	if err != nil {
		return err
	}
	defer w.close()

	depths := []int{1, 2, 3, 5, 8}
	for _, d := range depths {
		policy := depthPolicy(d)
		attrs := depthAttrs(d)
		setup, err := newBCABESetup(policy, attrs)
		if err != nil {
			return err
		}
		secret, _ := setup.engine.NewSecret()
		start := time.Now()
		ct, err := setup.engine.Encrypt(secret, setup.policy, setup.authpubs)
		if err != nil {
			return err
		}
		encMs := msSince(start)
		ctLen := len(abeengine.SerializeCiphertext(ct))

		start = time.Now()
		_, err = setup.engine.Decrypt(ct, setup.userattrs)
		if err != nil {
			return err
		}
		decMs := msSince(start)
		uaJSON := abeengine.SerializeUserAttrs(setup.userattrs)
		w.row(fmt.Sprint(d), policy, encMs, decMs, fmt.Sprint(ctLen), fmt.Sprint(len(uaJSON)))
	}
	return nil
}

func runBCABEMultiAuth(outDir string) error {
	w, err := newCSV(outDir, "bcabe_multi_auth.csv", []string{
		"step", "duration_ms", "size_bytes", "note",
	})
	if err != nil {
		return err
	}
	defer w.close()

	e0 := abeengine.NewEngine(benchSeed)
	if err := e0.InitOrg(); err != nil {
		return err
	}
	if err := e0.InitAuthority(); err != nil {
		return err
	}
	orgJSON := e0.OrgJSON()

	e1 := abeengine.NewEngine(benchSeed)
	if err := e1.LoadOrgFromJSON(orgJSON); err != nil {
		return err
	}
	if err := e1.InitAuthority(); err != nil {
		return err
	}

	policy := abeengine.NormalizePolicySyntax(multiAuthPolicy)
	authpubs := e0.AuthPubsOfPolicy(policy)
	authpubs.AuthPub["auth0"] = e0.AuthKeys().AuthPub
	authpubs.AuthPub["auth1"] = e1.AuthKeys().AuthPub

	secret, err := e0.NewSecret()
	if err != nil {
		return err
	}
	start := time.Now()
	ct, err := e0.Encrypt(secret, policy, authpubs)
	if err != nil {
		return err
	}
	w.row("encrypt", msSince(start), fmt.Sprint(len(abeengine.SerializeCiphertext(ct))), policy)

	var merged *abeengine.UserAttrs
	for _, spec := range multiAuthAttrs {
		var ua *abeengine.UserAttrs
		var issueErr error
		start = time.Now()
		if spec.engine == 0 {
			ua, issueErr = e0.IssueUserKey("alice", spec.attr)
		} else {
			ua, issueErr = e1.IssueUserKey("alice", spec.attr)
		}
		if issueErr != nil {
			return issueErr
		}
		w.row("IssueUserKey_"+spec.attr, msSince(start), "", "")
		merged = e0.MergeUserKeys(merged, ua)
	}
	for a := range merged.Userkey {
		merged.Coeff[a] = []int{}
	}

	start = time.Now()
	gotSecret, err := e0.Decrypt(ct, merged)
	if err != nil {
		return err
	}
	w.row("decrypt", msSince(start), "", "")
	wantKey, _ := abeengine.SymKeyFromSecret(secret)
	gotKey, _ := abeengine.SymKeyFromSecret(gotSecret)
	if string(wantKey[:]) != string(gotKey[:]) {
		return fmt.Errorf("multi-auth roundtrip key mismatch")
	}
	w.row("roundtrip", "0", "ok", "auth0+auth1")
	return nil
}

func ctJSONSize(v any) int {
	b, _ := json.Marshal(v)
	return len(b)
}

func runAESBench(outDir string) error {
	w, err := newCSV(outDir, "aes_compare.csv", []string{
		"content_bytes", "encrypt_ms", "decrypt_ms", "ciphertext_bytes",
	})
	if err != nil {
		return err
	}
	defer w.close()

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return err
	}
	var keyArr [32]byte
	copy(keyArr[:], key)

	sizes := []int{512, 1024, 4096, 16384, 65536}
	for _, size := range sizes {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i % 256)
		}
		start := time.Now()
		ct, err := aesEncrypt(keyArr, plain)
		if err != nil {
			return err
		}
		encMs := msSince(start)

		start = time.Now()
		if _, err = aesDecrypt(keyArr, ct); err != nil {
			return err
		}
		decMs := msSince(start)
		w.row(fmt.Sprint(size), encMs, decMs, fmt.Sprint(len(ct)))
	}
	return nil
}

func runGPSWBench(outDir string) error {
	w, err := newCSV(outDir, "gpsw_compare.csv", []string{
		"phase", "attr_count", "duration_ms", "ct_bytes", "key_bytes", "note",
	})
	if err != nil {
		return err
	}
	defer w.close()

	l := 16
	scheme := gofeabe.NewGPSW(l)

	start := time.Now()
	pubKey, secKey, err := scheme.GenerateMasterKeys()
	if err != nil {
		return err
	}
	w.row("setup", "", msSince(start), "", "", "universe=16")

	msg := string(make([]byte, 1024))
	for i := range msg {
		msg = msg[:i] + string(rune(byte(i%256))) + msg[i+1:]
	}
	msgBytes := make([]byte, 1024)
	for i := range msgBytes {
		msgBytes[i] = byte(i % 256)
	}
	msg = string(msgBytes)

	gamma, mspExpr := gpswPolicyForDepth(l, 3)
	msp, err := gofeabe.BooleanToMSP(mspExpr, true)
	if err != nil {
		return err
	}

	start = time.Now()
	cipher, err := scheme.Encrypt(msg, gamma, pubKey)
	if err != nil {
		return err
	}
	ctBytes := gpswCipherSize(cipher)
	w.row("encrypt", "3", msSince(start), fmt.Sprint(ctBytes), "", mspExpr)

	start = time.Now()
	abeKey, err := scheme.GeneratePolicyKey(msp, secKey)
	if err != nil {
		return err
	}
	keyBytes := gpswKeySize(abeKey)
	w.row("keygen", "3", msSince(start), "", fmt.Sprint(keyBytes), "")

	start = time.Now()
	got, err := scheme.Decrypt(cipher, abeKey)
	if err != nil {
		return err
	}
	if got != msg {
		return fmt.Errorf("gpsw roundtrip mismatch")
	}
	w.row("decrypt", "3", msSince(start), "", "", "")

	depths := []int{1, 2, 3, 5, 8}
	for _, d := range depths {
		if d > l {
			continue
		}
		g, expr := gpswPolicyForDepth(l, d)
		m, err := gofeabe.BooleanToMSP(expr, true)
		if err != nil {
			return err
		}
		start = time.Now()
		c, err := scheme.Encrypt(msg, g, pubKey)
		if err != nil {
			return err
		}
		encMs := msSince(start)
		start = time.Now()
		k, err := scheme.GeneratePolicyKey(m, secKey)
		if err != nil {
			return err
		}
		keyMs := msSince(start)
		start = time.Now()
		if _, err := scheme.Decrypt(c, k); err != nil {
			return err
		}
		decMs := msSince(start)
		w.row("depth_encrypt", fmt.Sprint(d), encMs, fmt.Sprint(gpswCipherSize(c)), fmt.Sprint(gpswKeySize(k)), expr)
		w.row("depth_keygen", fmt.Sprint(d), keyMs, "", "", "")
		w.row("depth_decrypt", fmt.Sprint(d), decMs, "", "", "")
	}
	return nil
}

func runSummaryCompare(outDir string) error {
	w, err := newCSV(outDir, "summary_compare.csv", []string{
		"scheme", "phase", "duration_ms", "size_bytes", "note",
	})
	if err != nil {
		return err
	}
	defer w.close()

	setup, err := newBCABESetup(defaultPolicy, defaultAttrs)
	if err != nil {
		return err
	}
	content := make([]byte, 1024)
	secret, _ := setup.engine.NewSecret()
	symKey, _ := abeengine.SymKeyFromSecret(secret)

	start := time.Now()
	ct, err := setup.engine.Encrypt(secret, setup.policy, setup.authpubs)
	if err != nil {
		return err
	}
	ctJSON := abeengine.SerializeCiphertext(ct)
	w.row("BC-ABE", "encrypt", msSince(start), fmt.Sprint(len(ctJSON)), "CP-ABE, 1KB hybrid")

	start = time.Now()
	if _, err = setup.engine.Decrypt(ct, setup.userattrs); err != nil {
		return err
	}
	w.row("BC-ABE", "decrypt", msSince(start), "", "")

	start = time.Now()
	encContent, _ := aesEncrypt(symKey, content)
	w.row("BC-ABE", "aes_encrypt", msSince(start), fmt.Sprint(len(encContent)), "content layer")

	key := make([]byte, 32)
	var keyArr [32]byte
	copy(keyArr[:], key)
	start = time.Now()
	aesCt, _ := aesEncrypt(keyArr, content)
	w.row("AES-GCM", "encrypt", msSince(start), fmt.Sprint(len(aesCt)), "1KB plaintext")

	start = time.Now()
	aesDecrypt(keyArr, aesCt)
	w.row("AES-GCM", "decrypt", msSince(start), "", "")

	l := 16
	scheme := gofeabe.NewGPSW(l)
	pubKey, secKey, _ := scheme.GenerateMasterKeys()
	msg := string(content)
	gamma, expr := gpswPolicyForDepth(l, 3)
	msp, _ := gofeabe.BooleanToMSP(expr, true)

	start = time.Now()
	gpswCt, _ := scheme.Encrypt(msg, gamma, pubKey)
	w.row("GPSW-KP", "encrypt", msSince(start), fmt.Sprint(gpswCipherSize(gpswCt)), "KP-ABE attrs="+expr)

	start = time.Now()
	gpswKey, _ := scheme.GeneratePolicyKey(msp, secKey)
	w.row("GPSW-KP", "keygen", msSince(start), fmt.Sprint(gpswKeySize(gpswKey)), "")

	start = time.Now()
	scheme.Decrypt(gpswCt, gpswKey)
	w.row("GPSW-KP", "decrypt", msSince(start), "", "")

	w.row("note", "semantic", "", "", "CP: ct=policy key=attrs; KP: ct=attrs key=policy")
	return w.close()
}

func gpswCipherSize(c *gofeabe.GPSWCipher) int {
	b, _ := json.Marshal(c)
	return len(b)
}

func gpswKeySize(k *gofeabe.GPSWKey) int {
	b, _ := json.Marshal(k)
	return len(b)
}

func runBCABEChainFlows(outDir string) error {
	cfg := config.Load()
	opts, err := gateway.DefaultOrg1Options(cfg.ChannelName, cfg.ChaincodeName)
	if err != nil {
		return fmt.Errorf("gateway options: %w", err)
	}
	gw, err := gateway.Init(opts)
	if err != nil {
		return fmt.Errorf("gateway init: %w", err)
	}

	w, err := newCSV(outDir, "bcabe_chain_flows.csv", []string{
		"phase", "step", "duration_ms", "size_bytes", "note",
	})
	if err != nil {
		return err
	}
	defer w.close()

	raw, err := gw.Contract().EvaluateTransaction("GetGlobalParams")
	if err != nil {
		return fmt.Errorf("GetGlobalParams: %w", err)
	}
	w.row("init", "GetGlobalParams", "", fmt.Sprint(len(raw)), "evaluate")

	paramsPayload, err := json.Marshal(map[string]any{
		"orgPubKeys": map[string]string{"bench-auth": "placeholder"},
		"version":    time.Now().UnixNano(),
	})
	if err != nil {
		return err
	}
	start := time.Now()
	if _, err := gw.Contract().SubmitTransaction("PutGlobalParams", string(paramsPayload)); err != nil {
		w.row("init", "PutGlobalParams", msSince(start), "", "failed: "+err.Error())
	} else {
		w.row("init", "PutGlobalParams", msSince(start), fmt.Sprint(len(paramsPayload)), "submit")
	}

	assetID := fmt.Sprintf("bench-%d", time.Now().UnixNano())
	asset := map[string]string{
		"id": assetID, "policy": defaultPolicy,
		"ciphertext": "{}", "owner": "0",
		"createdAt": time.Now().Format(time.RFC3339),
		"updatedAt": time.Now().Format(time.RFC3339),
	}
	assetJSON, _ := json.Marshal(asset)

	start = time.Now()
	if _, err := gw.Contract().SubmitTransaction("PutCiphertext", string(assetJSON)); err != nil {
		return fmt.Errorf("PutCiphertext: %w", err)
	}
	w.row("encrypt", "PutCiphertext", msSince(start), fmt.Sprint(len(assetJSON)), assetID)

	start = time.Now()
	got, err := gw.Contract().EvaluateTransaction("GetCiphertext", assetID)
	if err != nil {
		return fmt.Errorf("GetCiphertext: %w", err)
	}
	w.row("decrypt", "GetCiphertext", msSince(start), fmt.Sprint(len(got)), assetID)

	start = time.Now()
	if _, err := gw.Contract().SubmitTransaction("DeleteCiphertext", assetID); err != nil {
		w.row("cleanup", "DeleteCiphertext", msSince(start), "", err.Error())
	} else {
		w.row("cleanup", "DeleteCiphertext", msSince(start), "", "")
	}
	return nil
}

func runABETests(projectRoot string) error {
	abeDir := filepath.Join(projectRoot, "abe")
	cmd := exec.Command("go", "test", "./...", "-count=1")
	cmd.Dir = abeDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runSection(name string, fn func(string) error, outDir string) error {
	fmt.Println("==", name, "==")
	return fn(outDir)
}

func main() {
	out := flag.String("out", "../temp/bench", "CSV output directory")
	base := flag.String("base", "http://localhost:8080", "user_client URL for load test")
	conc := flag.Int("c", 10, "load concurrency")
	n := flag.Int("n", 50, "load requests per endpoint")
	skipTest := flag.Bool("skip-test", false, "skip abe unit tests")
	skipChain := flag.Bool("skip-chain", false, "skip Fabric chain benchmarks")
	skipLoad := flag.Bool("skip-load", false, "skip REST load test")
	flag.Parse()

	cfg := config.Load()
	logger.Init(cfg.LogDir, cfg.LogLevel)
	abeengine.InitLogging(cfg.LogDir, cfg.LogLevel)

	absOut, err := filepath.Abs(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("benchmark ->", absOut)

	if !*skipTest {
		if err := runSection("abe tests", func(string) error { return runABETests(cfg.ProjectRoot) }, absOut); err != nil {
			fmt.Fprintf(os.Stderr, "abe tests failed: %v\n", err)
			os.Exit(1)
		}
	}

	for _, s := range []struct {
		name string
		fn   func(string) error
	}{
		{"four flows", runBCABEFlows},
		{"varlen", runBCABEVarLen},
		{"policy depth", runBCABEDepth},
		{"multi auth", runBCABEMultiAuth},
		{"aes", runAESBench},
		{"gpsw", runGPSWBench},
		{"summary", runSummaryCompare},
	} {
		if err := runSection(s.name, s.fn, absOut); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.name, err)
			os.Exit(1)
		}
	}

	if !*skipChain {
		fmt.Println("== chain ==")
		if err := runBCABEChainFlows(absOut); err != nil {
			fmt.Fprintf(os.Stderr, "chain skipped: %v\n", err)
		}
	}

	if !*skipLoad {
		fmt.Println("== load ==")
		if err := runLoadTest(absOut, *base, *conc, *n); err != nil {
			fmt.Fprintf(os.Stderr, "load skipped: %v\n", err)
		}
	}

	fmt.Println("done, CSV under", absOut)
}
