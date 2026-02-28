// Package gemini implements the Google Gemini web API provider.
package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kyupark/ask/internal/provider"
)

const (
	geminiBaseURL = "https://gemini.google.com"
	geminiAPIURL  = "https://gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate"
	defaultBL     = "boq_assistant-bard-web-server_20260128.03_p2"

	batchExecURL          = "https://gemini.google.com/_/BardChatUi/data/batchexecute"
	rpcActivity           = "ESY5D"
	rpcDeleteConversation = "GzXR5e"

	cookiePSID   = "__Secure-1PSID"
	cookiePSIDTS = "__Secure-1PSIDTS"
	cookiePSIDCC = "__Secure-1PSIDCC"
	domainGoogle = "google.com"

	defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

var (
	reSnlm0e      = regexp.MustCompile(`"SNlM0e":"([^"]+)"`)
	reCfb2h       = regexp.MustCompile(`"cfb2h":"([^"]+)"`)
	reBl          = regexp.MustCompile(`"bl":"([^"]+)"`)
	numericLineRE = regexp.MustCompile(`^\d+$`)
)

// Provider implements the Gemini web API backend.
type Provider struct {
	userAgent    string
	timeout      time.Duration
	cookieHeader string

	// Scraped session tokens.
	snlm0e string
	cfb2h  string
	bl     string

	httpClient    *http.Client
	selectedModel string
}

// New creates a Gemini provider.
func New(userAgent string, timeout time.Duration) *Provider {
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	return &Provider{
		userAgent: userAgent,
		timeout:   timeout,
	}
}

func (p *Provider) Name() string { return "gemini" }

func (p *Provider) CookieSpecs() []provider.CookieSpec {
	return []provider.CookieSpec{
		{Domain: domainGoogle, Names: []string{cookiePSID, cookiePSIDTS, cookiePSIDCC}},
	}
}

func (p *Provider) SetCookies(cookies map[string]string) {
	// Build a full cookie header from all provided cookies.
	var pairs []string
	for k, v := range cookies {
		if v != "" {
			pairs = append(pairs, k+"="+v)
		}
	}
	if len(pairs) > 0 {
		p.cookieHeader = strings.Join(pairs, "; ")
	}
}

// SetModel sets the model to use for subsequent requests.
func (p *Provider) SetModel(model string) { p.selectedModel = model }
func (p *Provider) Ask(ctx context.Context, query string, opts provider.AskOptions) error {
	if p.cookieHeader == "" {
		return fmt.Errorf("no cookies — log in to gemini.google.com in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// Apply model selection.
	if opts.Model != "" {
		p.SetModel(opts.Model)
		logf("[gemini] model=%s", opts.Model)
	}

	// Initialize session tokens from the Gemini page.
	if p.snlm0e == "" {
		logf("[gemini] initializing session...")
		if err := p.initialize(ctx, logf); err != nil {
			return fmt.Errorf("initialize: %w", err)
		}
	}

	// Toggle activity (history) off if temporary mode.
	if opts.Temporary {
		logf("[gemini] temporary mode: disabling activity...")
		if err := p.setActivity(ctx, false, logf); err != nil {
			logf("[gemini] warning: could not disable activity: %v", err)
		}
	}
	// Send the chat request.
	resp, err := p.chat(ctx, query, opts.ConversationID, opts.ResponseID, logf)
	if err != nil {
		return err
	}
	if opts.OnConversation != nil {
		opts.OnConversation(resp.ConversationID, "", resp.ResponseID)
	}

	if opts.OnText != nil {
		opts.OnText(resp.Content)
	}
	if opts.OnDone != nil {
		opts.OnDone()
	}

	return nil
}

// --- Internal methods ---

func (p *Provider) initialize(ctx context.Context, logf func(string, ...any)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geminiBaseURL, nil)
	if err != nil {
		return err
	}

	p.setPageHeaders(req)
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("loading Gemini page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Gemini page returned %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading Gemini page: %w", err)
	}

	page := string(body)
	if m := reSnlm0e.FindStringSubmatch(page); len(m) == 2 {
		p.snlm0e = m[1]
	}
	if m := reCfb2h.FindStringSubmatch(page); len(m) == 2 {
		p.cfb2h = m[1]
	}
	if m := reBl.FindStringSubmatch(page); len(m) == 2 {
		p.bl = m[1]
	}

	if p.snlm0e == "" {
		if strings.Contains(page, "Sign in") || strings.Contains(page, "accounts.google.com") {
			return errors.New("not logged in — log in to gemini.google.com in your browser")
		}
		return errors.New("could not extract session token (SNlM0e) — API may have changed")
	}
	if p.bl == "" {
		p.bl = defaultBL
	}

	logf("[gemini] session initialized (bl=%s)", p.bl)
	return nil
}

// setActivity toggles Gemini activity (history saving) on or off.
// This sends a batchexecute RPC call before the chat request.
func (p *Provider) setActivity(ctx context.Context, enabled bool, logf func(string, ...any)) error {
	payloadStr := `[[["bard_activity_enabled"]]]`
	if !enabled {
		payloadStr = `[[["bard_activity_disabled"]]]`
	}

	// Serialize the batchexecute f.req payload:
	// [[[rpcID, innerPayload, null, "generic"]]]
	inner, err := json.Marshal([]any{[]any{[]any{rpcActivity, payloadStr, nil, "generic"}}})
	if err != nil {
		return fmt.Errorf("marshal activity payload: %w", err)
	}

	values := url.Values{}
	values.Set("f.req", string(inner))
	values.Set("at", p.snlm0e)

	params := url.Values{}
	params.Set("rpcids", rpcActivity)
	params.Set("source-path", "/app")
	params.Set("bl", p.bl)
	params.Set("_reqid", strconv.Itoa(rand.Intn(900000)+100000))
	params.Set("rt", "c")
	reqURL := batchExecURL + "?" + params.Encode()

	logf("[gemini] POST %s (activity=%v)", batchExecURL, enabled)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}

	p.setAPIHeaders(req)
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("activity request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("activity toggle returned %s: %s", resp.Status, string(body))
	}

	logf("[gemini] activity set to %v", enabled)
	return nil
}

type chatResponse struct {
	Success        bool
	Content        string
	ConversationID string
	ResponseID     string
}

func (p *Provider) chat(ctx context.Context, prompt, conversationID, responseID string, logf func(string, ...any)) (chatResponse, error) {
	const maxRetries = 3
	const baseDelayMs = 2000

	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := p.chatOnce(ctx, prompt, conversationID, responseID, logf)
		if err == nil && resp.Success {
			return resp, nil
		}

		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		if isRetryable(errMsg) && attempt < maxRetries {
			delay := time.Duration(baseDelayMs*(1<<attempt)) * time.Millisecond
			logf("[gemini] retry %d/%d after %dms: %s", attempt+1, maxRetries, delay.Milliseconds(), errMsg)
			time.Sleep(delay)
			continue
		}
		return resp, err
	}
	return chatResponse{}, errors.New("max retries exceeded")
}

func (p *Provider) chatOnce(ctx context.Context, prompt, conversationID, responseID string, logf func(string, ...any)) (chatResponse, error) {
	var convContext any
	if conversationID != "" {
		convContext = []any{conversationID, responseID, nil}
	}
	msg := []any{[]string{prompt}, nil, convContext}
	inner, err := json.Marshal(msg)
	if err != nil {
		return chatResponse{}, err
	}
	body, err := json.Marshal([]any{nil, string(inner)})
	if err != nil {
		return chatResponse{}, err
	}

	values := url.Values{}
	values.Set("f.req", string(body))
	values.Set("at", p.snlm0e)

	params := url.Values{}
	params.Set("bl", p.bl)
	params.Set("_reqid", strconv.Itoa(rand.Intn(900000)+100000))
	params.Set("rt", "c")
	reqURL := geminiAPIURL + "?" + params.Encode()

	logf("[gemini] POST %s", geminiAPIURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return chatResponse{}, err
	}

	p.setAPIHeaders(req)
	resp, err := p.client().Do(req)
	if err != nil {
		return chatResponse{}, err
	}
	defer resp.Body.Close()

	text, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return chatResponse{}, fmt.Errorf("API returned %s", resp.Status)
	}

	logf("[gemini] response length: %d bytes", len(text))
	result, err := parseChatResponse(string(text))
	if err != nil {
		// Log a snippet of the raw response for debugging.
		snippet := string(text)
		if len(snippet) > 500 {
			snippet = snippet[:500] + "..."
		}
		logf("[gemini] parse failed, raw response: %s", snippet)
	}
	return result, err
}

func (p *Provider) client() *http.Client {
	if p.httpClient == nil {
		p.httpClient = &http.Client{Timeout: p.timeout}
	}
	return p.httpClient
}

func (p *Provider) setPageHeaders(req *http.Request) {
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Cookie", p.cookieHeader)
}

func (p *Provider) setAPIHeaders(req *http.Request) {
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Set("Origin", geminiBaseURL)
	req.Header.Set("Referer", geminiBaseURL+"/")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("X-Same-Domain", "1")
	req.Header.Set("Cookie", p.cookieHeader)
	// Set model-specific header for non-default models.
	if h := ResolveModelHeader(p.selectedModel); h != "" {
		req.Header.Set("x-goog-ext-525001261-jspb", h)
	}
}

// --- Response parsing ---

func parseChatResponse(text string) (chatResponse, error) {
	if strings.HasPrefix(text, ")]}'") {
		text = text[4:]
	}
	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || numericLineRE.MatchString(line) {
			continue
		}
		var parsed any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			continue
		}
		resp, ok := parseChatNode(parsed)
		if ok && resp.Success {
			return resp, nil
		}
	}
	return chatResponse{}, errors.New("could not parse Gemini response")
}

func parseChatNode(node any) (chatResponse, bool) {
	switch v := node.(type) {
	case []any:
		if len(v) >= 3 && v[0] == "wrb.fr" {
			if innerText, ok := v[2].(string); ok {
				var inner any
				if err := json.Unmarshal([]byte(innerText), &inner); err == nil {
					resp := parseChatInner(inner)
					if resp.Success {
						return resp, true
					}
				}
			}
		}
		for _, child := range v {
			if resp, ok := parseChatNode(child); ok {
				return resp, true
			}
		}
	case map[string]any:
		for _, child := range v {
			if resp, ok := parseChatNode(child); ok {
				return resp, true
			}
		}
	}
	return chatResponse{}, false
}

func parseChatInner(inner any) chatResponse {
	arr, ok := inner.([]any)
	if !ok || len(arr) == 0 {
		return chatResponse{}
	}

	convID := ""
	respID := ""
	if len(arr) > 1 {
		if pair, ok := arr[1].([]any); ok && len(pair) >= 2 {
			if v, ok := pair[0].(string); ok {
				convID = v
			}
			if v, ok := pair[1].(string); ok {
				respID = v
			}
		}
	}

	if text, ok := findResponseText(arr); ok {
		return chatResponse{
			Success:        true,
			Content:        text,
			ConversationID: convID,
			ResponseID:     respID,
		}
	}

	for _, child := range arr {
		if resp, ok := parseChatNode(child); ok && resp.Success && resp.Content != "" {
			if resp.ConversationID == "" {
				resp.ConversationID = convID
			}
			if resp.ResponseID == "" {
				resp.ResponseID = respID
			}
			return resp
		}
	}

	return chatResponse{}
}

func findResponseText(node any) (string, bool) {
	switch v := node.(type) {
	case []any:
		if len(v) >= 2 {
			if _, ok := v[0].(string); ok {
				if text, ok := textFromCandidate(v[1]); ok && isLikelyText(text) {
					return text, true
				}
			}
		}
		for _, child := range v {
			if text, ok := findResponseText(child); ok {
				return text, true
			}
		}
	case map[string]any:
		for _, child := range v {
			if text, ok := findResponseText(child); ok {
				return text, true
			}
		}
	}
	return "", false
}

func textFromCandidate(v any) (string, bool) {
	switch value := v.(type) {
	case string:
		if text := strings.TrimSpace(value); text != "" {
			return text, true
		}
		return "", false
	case []any:
		for _, item := range value {
			if text, ok := textFromCandidate(item); ok {
				return text, true
			}
		}
	}
	return "", false
}

func isLikelyText(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return false
	}
	// Filter out known ID prefixes that appear in Gemini responses.
	for _, prefix := range []string{"c_", "rc_", "r_", "b_"} {
		if strings.HasPrefix(text, prefix) {
			return false
		}
	}
	// Filter out short hex-like IDs (e.g. "abc123def456").
	if len(text) < 40 && !strings.Contains(text, " ") {
		return false
	}
	return true
}

func isRetryable(msg string) bool {
	return strings.Contains(msg, "429") || strings.Contains(msg, "500") ||
		strings.Contains(msg, "502") || strings.Contains(msg, "503")
}

func (p *Provider) DeleteConversation(ctx context.Context, conversationID string, opts provider.DeleteOptions) error {
	if p.cookieHeader == "" {
		return fmt.Errorf("no cookies — log in to gemini.google.com in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if p.snlm0e == "" {
		if err := p.initialize(ctx, logf); err != nil {
			return fmt.Errorf("initialize: %w", err)
		}
	}

	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return fmt.Errorf("conversation ID is required")
	}
	if !strings.HasPrefix(conversationID, "c_") {
		conversationID = "c_" + conversationID
	}

	innerPayload, _ := json.Marshal([]any{conversationID})
	reqBody, _ := json.Marshal([]any{[]any{[]any{rpcDeleteConversation, string(innerPayload), nil, "generic"}}})

	values := url.Values{}
	values.Set("f.req", string(reqBody))
	values.Set("at", p.snlm0e)

	params := url.Values{}
	params.Set("rpcids", rpcDeleteConversation)
	params.Set("source-path", "/app")
	params.Set("bl", p.bl)
	params.Set("_reqid", strconv.Itoa(rand.Intn(900000)+100000))
	params.Set("rt", "c")
	reqURL := batchExecURL + "?" + params.Encode()

	logf("[gemini] POST %s (rpc=%s)", batchExecURL, rpcDeleteConversation)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	p.setAPIHeaders(req)

	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("delete request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("delete conversation HTTP %s: %s", resp.Status, string(body))
	}

	logf("[gemini] conversation deleted")
	return nil
}

// --- List conversations ---

const rpcListConversations = "MaZiqc"

// ListConversations fetches recent conversations via the MaZiqc batchexecute RPC.
func (p *Provider) ListConversations(ctx context.Context, opts provider.ListOptions) ([]provider.Conversation, error) {
	if p.cookieHeader == "" {
		return nil, fmt.Errorf("no cookies \u2014 log in to gemini.google.com in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if p.snlm0e == "" {
		logf("[gemini] initializing session for list...")
		if err := p.initialize(ctx, logf); err != nil {
			return nil, fmt.Errorf("initialize: %w", err)
		}
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}

	// Build the batchexecute payload: [count, null, [0, null, 1]]
	innerPayload, _ := json.Marshal([]any{limit, nil, []any{0, nil, 1}})
	reqBody, _ := json.Marshal([]any{[]any{[]any{rpcListConversations, string(innerPayload), nil, "generic"}}})

	values := url.Values{}
	values.Set("f.req", string(reqBody))
	values.Set("at", p.snlm0e)

	params := url.Values{}
	params.Set("rpcids", rpcListConversations)
	params.Set("source-path", "/app")
	params.Set("bl", p.bl)
	params.Set("_reqid", strconv.Itoa(rand.Intn(900000)+100000))
	params.Set("rt", "c")
	reqURL := batchExecURL + "?" + params.Encode()

	logf("[gemini] POST %s (rpc=%s)", batchExecURL, rpcListConversations)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	p.setAPIHeaders(req)

	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("list request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("list conversations HTTP %s: %s", resp.Status, string(body))
	}

	text, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseListResponse(string(text), logf)
}

func parseListResponse(text string, logf func(string, ...any)) ([]provider.Conversation, error) {
	if strings.HasPrefix(text, ")]}'\n") {
		text = text[5:]
	} else if strings.HasPrefix(text, ")]}'") {
		text = text[4:]
	}

	lines := strings.Split(text, "\n")
	var conversations []provider.Conversation

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || numericLineRE.MatchString(line) {
			continue
		}

		var parsed any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			continue
		}

		extractConversations(parsed, &conversations)
	}

	logf("[gemini] fetched %d conversations", len(conversations))
	return conversations, nil
}

func extractConversations(node any, out *[]provider.Conversation) {
	arr, ok := node.([]any)
	if !ok {
		return
	}

	// Look for wrb.fr wrapper with MaZiqc
	if len(arr) >= 3 {
		if tag, ok := arr[0].(string); ok && tag == "wrb.fr" {
			if innerStr, ok := arr[2].(string); ok {
				var inner any
				if err := json.Unmarshal([]byte(innerStr), &inner); err == nil {
					extractConversationsFromInner(inner, out)
					return
				}
			}
		}
	}

	// Recurse into arrays
	for _, child := range arr {
		extractConversations(child, out)
	}
}

func extractConversationsFromInner(node any, out *[]provider.Conversation) {
	arr, ok := node.([]any)
	if !ok {
		return
	}

	for _, item := range arr {
		itemArr, ok := item.([]any)
		if !ok || len(itemArr) < 2 {
			continue
		}

		// Gemini conversation entries: [id, title, ...]
		// where id starts with "c_"
		id, idOK := itemArr[0].(string)
		if !idOK || !strings.HasPrefix(id, "c_") {
			// Try nested arrays
			if _, ok := itemArr[0].([]any); ok {
				extractConversationsFromInner(item, out)
			}
			continue
		}

		title := ""
		if t, ok := itemArr[1].(string); ok {
			title = t
		}

		// Deduplicate
		dupe := false
		for _, existing := range *out {
			if existing.ID == id {
				dupe = true
				break
			}
		}
		if !dupe {
			*out = append(*out, provider.Conversation{
				ID:    id,
				Title: title,
			})
		}
	}
}

// --- Model catalog ---

// geminiModelHeaders maps model names to the x-goog-ext-525001261-jspb header value.
var geminiModelHeaders = map[string]string{
	"gemini-3-pro":            `[1,null,null,null,"9d8ca3786ebdfbea",null,null,0,[4],null,null,1]`,
	"gemini-3-flash":          `[1,null,null,null,"fbb127bbb056c959",null,null,0,[4],null,null,1]`,
	"gemini-3-flash-thinking": `[1,null,null,null,"5bf011840784117a",null,null,0,[4],null,null,1]`,
	"gemini-2.5-pro":          `[1,null,null,null,"61530e79959ab139",null,null,null,[4]]`,
	"gemini-2.5-flash":        `[1,null,null,null,"9ec249fc9ad08861",null,null,null,[4]]`,
	"gemini-2.0-flash":        `[null,null,null,null,"f299729663a2343f"]`,
	"gemini-deep-research":    `[1,null,null,null,"cd472a54d2abba7e"]`,
}

// ResolveModelHeader returns the x-goog-ext header value for a model, or empty string for default.
func ResolveModelHeader(model string) string {
	if model == "" {
		return ""
	}
	if h, ok := geminiModelHeaders[model]; ok {
		return h
	}
	return ""
}

// ListModels returns the available Gemini models.
func (p *Provider) ListModels() provider.ProviderModels {
	return provider.ProviderModels{
		Provider: "gemini",
		Models: []provider.ModelInfo{
			{ID: "gemini-3-pro", Name: "Gemini 3 Pro", Description: "Latest flagship model", Default: true, Tags: []string{"flagship"}},
			{ID: "gemini-3-flash", Name: "Gemini 3 Flash", Description: "Fast and efficient", Default: false, Tags: []string{"fast"}},
			{ID: "gemini-3-flash-thinking", Name: "Gemini 3 Flash Thinking", Description: "Flash with reasoning", Default: false, Tags: []string{"fast", "reasoning"}},
			{ID: "gemini-2.5-pro", Name: "Gemini 2.5 Pro", Description: "Previous-gen Pro model", Default: false, Tags: []string{"flagship"}},
			{ID: "gemini-2.5-flash", Name: "Gemini 2.5 Flash", Description: "Previous-gen Flash model", Default: false, Tags: []string{"fast"}},
			{ID: "gemini-2.0-flash", Name: "Gemini 2.0 Flash", Description: "Legacy Flash model", Default: false, Tags: []string{"fast", "legacy"}},
			{ID: "gemini-deep-research", Name: "Gemini Deep Research", Description: "Multi-step research agent", Default: false, Tags: []string{"deep-research"}},
		},
	}
}
