package grok

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kyupark/ask/internal/httpclient"
	"github.com/kyupark/ask/internal/provider"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// --- constants ---

const (
	twitterAPIBase          = "https://x.com/i/api/graphql"
	grokAddResponseURL      = "https://grok.x.com/2/grok/add_response.json"
	grokAddResponseFallback = "https://api.x.com/2/grok/add_response.json"
	grokAddResponseLegacy   = "https://x.com/i/api/2/grok/add_response.json"

	bearerToken = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"

	cookieAuthToken = "auth_token"
	cookieCT0       = "ct0"
	domainX         = "x.com"
)

// Fallback query IDs — these rotate server-side; we try them in order.
var fallbackQueryIDs = map[string][]string{
	"CreateGrokConversation":        {"vvC5uy7pWWHXS2aDi1FZeA"},
	"GrokConversationItemsByRestId": {"6QmFgXuRQyOnW2iJ7nIk7g"},
}

// --- model aliases ---

var modelAliases = map[string]string{
	"auto":           "grok-4-auto",
	"fast":           "grok-4-fast-non-reasoning",
	"expert":         "grok-4",
	"heavy":          "grok-4",
	"thinking":       "grok-4.1-fast-reasoning",
	"4.20":           "grok-420",
	"420":            "grok-420",
	"4":              "grok-4-auto",
	"3":              "grok-3",
	"2":              "grok-2a",
	"mini":           "grok-3-mini",
	"grok-4-heavy":   "grok-4",
	"grok-4.20":      "grok-420",
	"grok-4.20-beta": "grok-420",
	"grok-420":       "grok-420",
}

// ResolveModel maps a user-friendly alias to the full model ID.
func ResolveModel(input string) string {
	if input == "" {
		return "grok-420"
	}
	lower := strings.ToLower(input)
	if alias, ok := modelAliases[lower]; ok {
		return alias
	}
	return input
}

// --- feature flags ---

func buildGrokFeatures() map[string]bool {
	return map[string]bool{
		"responsive_web_graphql_timeline_navigation_enabled":                      true,
		"responsive_web_graphql_exclude_directive_enabled":                        true,
		"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
		"rweb_video_screen_enabled":                                               true,
		"view_counts_everywhere_api_enabled":                                      true,
		"responsive_web_profile_redirect_enabled":                                 true,
		"profile_label_improvements_pcf_label_in_post_enabled":                    true,
		"creator_subscriptions_tweet_preview_api_enabled":                         true,
		"creator_subscriptions_quote_tweet_preview_enabled":                       false,
		"communities_web_enable_tweet_community_results_fetch":                    true,
		"longform_notetweets_consumption_enabled":                                 true,
		"longform_notetweets_rich_text_read_enabled":                              true,
		"longform_notetweets_inline_media_enabled":                                true,
		"responsive_web_edit_tweet_api_enabled":                                   true,
		"responsive_web_twitter_article_tweet_consumption_enabled":                true,
		"articles_preview_enabled":                                                true,
		"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
		"freedom_of_speech_not_reach_fetch_enabled":                               true,
		"standardized_nudges_misinfo":                                             true,
		"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
		"verified_phone_label_enabled":                                            false,
		"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
		"rweb_tipjar_consumption_enabled":                                         true,
		"tweet_awards_web_tipping_enabled":                                        false,
		"premium_content_api_read_enabled":                                        false,
		"responsive_web_jetfuel_frame":                                            true,
		"post_ctas_fetch_enabled":                                                 true,
		"responsive_web_enhance_cards_enabled":                                    false,
		"responsive_web_grok_analyze_button_fetch_trends_enabled":                 true,
		"responsive_web_grok_analyze_post_followups_enabled":                      true,
		"responsive_web_grok_annotations_enabled":                                 true,
		"responsive_web_grok_share_attachment_enabled":                            true,
		"responsive_web_grok_show_grok_translated_post":                           true,
		"responsive_web_grok_analysis_button_from_backend":                        true,
		"responsive_web_grok_image_annotation_enabled":                            true,
		"responsive_web_grok_imagine_annotation_enabled":                          true,
		"responsive_web_grok_community_note_auto_translation_is_enabled":          true,
		"rweb_video_timestamps_enabled":                                           true,
		"responsive_web_twitter_article_plain_text_enabled":                       true,
		"responsive_web_twitter_article_seed_tweet_detail_enabled":                true,
		"responsive_web_twitter_article_seed_tweet_summary_enabled":               true,
	}
}

// --- Provider ---

// Provider implements provider.Provider for Grok on X.com.
type Provider struct {
	userAgent string
	timeout   time.Duration
	authToken string
	ct0       string

	txnGen     *transactionGenerator
	deepsearch bool
	reasoning  bool
}

// New creates a Grok provider.
func New(userAgent string, timeout time.Duration) *Provider {
	return &Provider{
		userAgent: userAgent,
		timeout:   timeout,
	}
}

func (p *Provider) Name() string { return "grok" }

func (p *Provider) CookieSpecs() []provider.CookieSpec {
	return []provider.CookieSpec{
		{Domain: domainX, Names: []string{cookieAuthToken, cookieCT0}},
	}
}

func (p *Provider) SetCookies(cookies map[string]string) {
	if v := cookies[cookieAuthToken]; v != "" {
		p.authToken = v
	}
	if v := cookies[cookieCT0]; v != "" {
		p.ct0 = v
	}
}

// SetDeepSearch enables or disables deep search mode.
func (p *Provider) SetDeepSearch(enabled bool) { p.deepsearch = enabled }

// SetReasoning enables or disables reasoning mode.
func (p *Provider) SetReasoning(enabled bool) { p.reasoning = enabled }
func (p *Provider) Ask(ctx context.Context, query string, opts provider.AskOptions) error {
	if p.authToken == "" || p.ct0 == "" {
		return fmt.Errorf("missing X.com cookies (auth_token, ct0) — log into x.com in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// Lazily init the transaction generator.
	if p.txnGen == nil {
		p.txnGen = newTransactionGenerator(p.userAgent, logf)
	}

	model := ResolveModel(opts.Model)
	logf("[grok] model=%s temporary=%v", model, opts.Temporary)

	// 1. Create conversation unless continuing.
	conversationID := opts.ConversationID
	var err error
	if conversationID == "" {
		conversationID, err = p.createConversation(ctx, logf)
		if err != nil {
			return fmt.Errorf("creating conversation: %w", err)
		}
	}
	logf("[grok] conversation=%s", conversationID)

	// 2. Send message + stream NDJSON response.
	if err := p.sendMessage(ctx, conversationID, query, model, opts); err != nil {
		return err
	}
	if opts.OnConversation != nil {
		opts.OnConversation(conversationID, "", "")
	}
	return nil
}

// --- internal API methods ---

func (p *Provider) cookieHeader() string {
	return fmt.Sprintf("auth_token=%s; ct0=%s", p.authToken, p.ct0)
}

func (p *Provider) baseHeaders() map[string]string {
	return map[string]string{
		"accept":                    "*/*",
		"accept-language":           "en-US,en;q=0.9",
		"authorization":             "Bearer " + bearerToken,
		"x-csrf-token":              p.ct0,
		"x-twitter-auth-type":       "OAuth2Session",
		"x-twitter-active-user":     "yes",
		"x-twitter-client-language": "en",
		"x-client-transaction-id":   generateRandomTransactionID(),
		"cookie":                    p.cookieHeader(),
		"user-agent":                p.userAgent,
		"origin":                    "https://x.com",
		"referer":                   "https://x.com/",
	}
}

func (p *Provider) grokHeaders() map[string]string {
	h := p.baseHeaders()
	h["content-type"] = "application/json"
	h["referer"] = "https://x.com/i/grok"
	return h
}

func (p *Provider) grokWriteHeaders(method, endpointURL string) map[string]string {
	h := p.grokHeaders()
	parsed, err := url.Parse(endpointURL)
	path := endpointURL
	if err == nil {
		path = parsed.Path
	}
	if p.txnGen != nil {
		txnID, err := p.txnGen.generateID(method, path)
		if err == nil {
			h["x-client-transaction-id"] = txnID
		}
	}
	return h
}

func (p *Provider) doRequest(ctx context.Context, method, reqURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := httpclient.New(p.timeout)
	return client.Do(req)
}

func (p *Provider) createConversation(ctx context.Context, logf func(string, ...any)) (string, error) {
	features := buildGrokFeatures()

	for _, queryID := range fallbackQueryIDs["CreateGrokConversation"] {
		apiURL := fmt.Sprintf("%s/%s/CreateGrokConversation", twitterAPIBase, queryID)
		body := map[string]any{
			"variables": map[string]any{},
			"features":  features,
			"queryId":   queryID,
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return "", err
		}

		logf("[grok] POST %s", apiURL)
		resp, err := p.doRequest(ctx, "POST", apiURL, bytes.NewReader(bodyJSON), p.grokHeaders())
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			text, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return "", fmt.Errorf("create conversation HTTP %d: %s", resp.StatusCode, string(text))
		}

		text, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		var payload map[string]any
		if err := json.Unmarshal(text, &payload); err != nil {
			return "", fmt.Errorf("parsing create response: %w", err)
		}

		convID := extractConversationID(payload)
		if convID == "" {
			return "", fmt.Errorf("conversation ID not found in response: %s", truncStr(string(text), 200))
		}
		return convID, nil
	}

	return "", fmt.Errorf("all CreateGrokConversation query IDs exhausted")
}

func (p *Provider) sendMessage(ctx context.Context, conversationID, query, model string, opts provider.AskOptions) error {
	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	payload := map[string]any{
		"responses": []any{
			map[string]any{
				"message":         query,
				"sender":          1,
				"fileAttachments": []any{},
			},
		},
		"systemPromptName":    "",
		"grokModelOptionId":   model,
		"conversationId":      conversationID,
		"returnSearchResults": true,
		"returnCitations":     true,
		"promptMetadata": map[string]any{
			"promptSource": "NATURAL",
			"action":       "INPUT",
		},
		"imageGenerationCount": 4,
		"requestFeatures": map[string]any{
			"eagerTweets":   true,
			"serverHistory": true,
		},
	}

	// Apply deepsearch/reasoning mode overrides.
	if p.deepsearch {
		payload["isDeepsearch"] = true
	}
	if p.reasoning {
		payload["isReasoning"] = true
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling payload: %w", err)
	}

	endpoints := []string{grokAddResponseURL, grokAddResponseFallback, grokAddResponseLegacy}
	var lastErr error

	for sweep := 0; sweep < 3; sweep++ {
		all404 := true
		for _, endpoint := range endpoints {
			headers := p.grokWriteHeaders("POST", endpoint)
			headers["content-type"] = "text/plain;charset=UTF-8"

			logf("[grok] POST %s txn=%s (sweep=%d)", endpoint, headers["x-client-transaction-id"], sweep+1)
			resp, err := p.doRequest(ctx, "POST", endpoint, bytes.NewReader(payloadJSON), headers)
			if err != nil {
				all404 = false
				lastErr = err
				continue
			}
			logf("[grok] response status=%d proto=%s", resp.StatusCode, resp.Proto)
			for k, vals := range resp.Header {
				for _, v := range vals {
					logf("[grok]   header %s: %s", k, v)
				}
			}
			if resp.StatusCode == 404 {
				resp.Body.Close()
				continue
			}
			all404 = false
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncStr(string(body), 200))
				continue
			}
			// Read full body for debugging, then parse NDJSON.
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return fmt.Errorf("reading grok response: %w", readErr)
			}
			logf("[grok] raw response (%d bytes): %s", len(bodyBytes), truncStr(string(bodyBytes), 500))
			if len(bodyBytes) == 0 {
				return p.emitFallbackMessage(ctx, conversationID, opts, logf)
			}

			sawText := false
			wrapped := opts
			wrapped.OnText = func(text string) {
				if strings.TrimSpace(text) != "" {
					sawText = true
				}
				if opts.OnText != nil {
					opts.OnText(text)
				}
			}

			if err := p.readNDJSON(bytes.NewReader(bodyBytes), wrapped); err != nil {
				return err
			}
			if sawText {
				return nil
			}
			return p.emitFallbackMessage(ctx, conversationID, opts, logf)
		}

		if all404 && sweep < 2 {
			logf("[grok] all add_response endpoints returned 404; retrying sweep")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(250*(sweep+1)) * time.Millisecond):
			}
			continue
		}
		break
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("all Grok endpoints failed")
}

func (p *Provider) emitFallbackMessage(ctx context.Context, conversationID string, opts provider.AskOptions, logf func(string, ...any)) error {
	var text string
	var err error
	for i := 0; i < 10; i++ {
		text, err = p.fetchLatestAssistantMessage(ctx, conversationID, logf)
		if err != nil {
			return err
		}
		if strings.TrimSpace(text) != "" {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if strings.TrimSpace(text) == "" {
		logf("[grok] fallback conversation fetch returned empty assistant message")
		if opts.OnDone != nil {
			opts.OnDone()
		}
		return nil
	}
	if opts.OnText != nil {
		opts.OnText(text)
	}
	if opts.OnDone != nil {
		opts.OnDone()
	}
	return nil
}

func (p *Provider) fetchLatestAssistantMessage(ctx context.Context, conversationID string, logf func(string, ...any)) (string, error) {
	features := buildGrokFeatures()
	variables := map[string]any{"restId": conversationID}

	variablesJSON, err := json.Marshal(variables)
	if err != nil {
		return "", err
	}
	featuresJSON, err := json.Marshal(features)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Set("variables", string(variablesJSON))
	params.Set("features", string(featuresJSON))

	for _, queryID := range fallbackQueryIDs["GrokConversationItemsByRestId"] {
		apiURL := fmt.Sprintf("%s/%s/GrokConversationItemsByRestId?%s", twitterAPIBase, queryID, params.Encode())
		resp, err := p.doRequest(ctx, "GET", apiURL, nil, p.grokHeaders())
		if err != nil {
			continue
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return "", readErr
		}
		if resp.StatusCode == 404 {
			logf("[grok] fallback conversation query %s returned 404", queryID)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			logf("[grok] fallback conversation HTTP %d body=%s", resp.StatusCode, truncStr(string(body), 300))
			return "", fmt.Errorf("fetch conversation HTTP %d: %s", resp.StatusCode, truncStr(string(body), 200))
		}
		logf("[grok] fallback conversation body: %s", truncStr(string(body), 300))

		var payload struct {
			Data struct {
				Conversation *struct {
					Messages []struct {
						Message string `json:"message"`
						Sender  int    `json:"sender"`
					} `json:"messages"`
					Items []struct {
						Message    string `json:"message"`
						SenderType string `json:"sender_type"`
					} `json:"items"`
				} `json:"grok_conversation_items_by_rest_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", fmt.Errorf("parsing conversation response: %w", err)
		}

		if payload.Data.Conversation == nil {
			return "", nil
		}

		for i := len(payload.Data.Conversation.Items) - 1; i >= 0; i-- {
			item := payload.Data.Conversation.Items[i]
			sender := strings.ToLower(item.SenderType)
			if (sender == "agent" || sender == "assistant" || sender == "grok") && strings.TrimSpace(item.Message) != "" {
				return item.Message, nil
			}
		}
		for i := len(payload.Data.Conversation.Messages) - 1; i >= 0; i-- {
			msg := payload.Data.Conversation.Messages[i]
			if msg.Sender == 2 && strings.TrimSpace(msg.Message) != "" {
				return msg.Message, nil
			}
		}
		return "", nil
	}

	return "", fmt.Errorf("all GrokConversationItemsByRestId query IDs exhausted")
}

// readNDJSON reads newline-delimited JSON from r, calling opts.OnText
// for each message chunk. This provides real-time streaming output.
func (p *Provider) readNDJSON(r io.Reader, opts provider.AskOptions) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var obj struct {
			Result struct {
				Message string `json:"message"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		if obj.Result.Message != "" && opts.OnText != nil {
			opts.OnText(obj.Result.Message)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading NDJSON stream: %w", err)
	}

	if opts.OnDone != nil {
		opts.OnDone()
	}
	return nil
}

// --- helpers ---

func extractConversationID(payload map[string]any) string {
	data, ok := payload["data"].(map[string]any)
	if !ok {
		return ""
	}
	for _, candidate := range data {
		obj, ok := candidate.(map[string]any)
		if !ok {
			continue
		}
		if restID, ok := obj["rest_id"].(string); ok && restID != "" {
			return restID
		}
		if id, ok := obj["id"].(string); ok && id != "" {
			return id
		}
		if convID, ok := obj["conversation_id"].(string); ok && convID != "" {
			return convID
		}
	}
	return ""
}

func truncStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// --- List conversations ---

var fallbackGrokHistoryQueryIDs = []string{"9Hyh5D4-WXLnExZkONSkZg"}

type rawGrokHistoryItem struct {
	CreatedAtMs      int64 `json:"created_at_ms"`
	IsPinned         bool  `json:"is_pinned"`
	GrokConversation *struct {
		ID     string `json:"id"`
		RestID string `json:"rest_id"`
	} `json:"grokConversation"`
	Title string `json:"title"`
}

// ListConversations fetches recent Grok conversations via the GrokHistory GraphQL query.
func (p *Provider) ListConversations(ctx context.Context, opts provider.ListOptions) ([]provider.Conversation, error) {
	if p.authToken == "" || p.ct0 == "" {
		return nil, fmt.Errorf("missing X.com cookies (auth_token, ct0) \u2014 log into x.com in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}

	features := buildGrokFeatures()

	for _, queryID := range fallbackGrokHistoryQueryIDs {
		variables := map[string]any{
			"count": limit,
		}

		variablesJSON, _ := json.Marshal(variables)
		featuresJSON, _ := json.Marshal(features)

		params := url.Values{}
		params.Set("variables", string(variablesJSON))
		params.Set("features", string(featuresJSON))

		apiURL := fmt.Sprintf("%s/%s/GrokHistory?%s", twitterAPIBase, queryID, params.Encode())
		logf("[grok] GET %s", apiURL)

		resp, err := p.doRequest(ctx, "GET", apiURL, nil, p.grokHeaders())
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return nil, fmt.Errorf("list conversations HTTP %d: %s", resp.StatusCode, string(body))
		}

		var data struct {
			Data struct {
				GrokConversationHistory struct {
					Items  []rawGrokHistoryItem `json:"items"`
					Cursor string               `json:"cursor"`
				} `json:"grok_conversation_history"`
			} `json:"data"`
		}
		text, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(text, &data); err != nil {
			return nil, fmt.Errorf("parsing history response: %w", err)
		}

		var result []provider.Conversation
		for _, item := range data.Data.GrokConversationHistory.Items {
			id := ""
			if item.GrokConversation != nil {
				id = item.GrokConversation.RestID
				if id == "" {
					id = item.GrokConversation.ID
				}
			}
			c := provider.Conversation{
				ID:    id,
				Title: item.Title,
			}
			if item.CreatedAtMs > 0 {
				c.CreatedAt = time.Unix(item.CreatedAtMs/1000, (item.CreatedAtMs%1000)*1e6)
			}
			result = append(result, c)
		}

		logf("[grok] fetched %d conversations", len(result))
		return result, nil
	}

	return nil, fmt.Errorf("all GrokHistory query IDs exhausted")
}

// --- Model catalog ---

// ListModels returns the available Grok models and modes.
func (p *Provider) ListModels() provider.ProviderModels {
	return provider.ProviderModels{
		Provider: "grok",
		Models: []provider.ModelInfo{
			{ID: "grok-4-auto", Name: "Grok 4 Auto", Description: "Auto-select model", Default: false, Tags: []string{"auto"}},
			{ID: "grok-4-fast-non-reasoning", Name: "Grok 4 Fast", Description: "Fast, no reasoning", Default: false, Tags: []string{"fast"}},
			{ID: "grok-4", Name: "Grok 4 Expert", Description: "Expert model", Default: false, Tags: []string{"flagship"}},
			{ID: "grok-420", Name: "Grok 4.20 Beta", Description: "Early-access Grok 4.20 model", Default: true, Tags: []string{"beta", "reasoning"}},
			{ID: "grok-4.1-fast-reasoning", Name: "Grok 4.1 Thinking", Description: "Fast reasoning model", Default: false, Tags: []string{"reasoning"}},
			{ID: "grok-3", Name: "Grok 3", Description: "Previous generation model", Default: false, Tags: []string{"legacy"}},
			{ID: "grok-3-mini", Name: "Grok 3 Mini", Description: "Lightweight model", Default: false, Tags: []string{"fast", "legacy"}},
			{ID: "grok-2a", Name: "Grok 2", Description: "Grok 2 model", Default: false, Tags: []string{"legacy"}},
		},
		Modes: []provider.ModeInfo{
			{ID: "normal", Name: "Normal", Description: "Standard response", Default: true},
			{ID: "deepsearch", Name: "DeepSearch", Description: "Deep web search mode (isDeepsearch=true)", Default: false},
			{ID: "reasoning", Name: "Reasoning", Description: "Reasoning mode (isReasoning=true)", Default: false},
		},
	}
}

// ModelAliases returns the user-friendly alias map for display.
func ModelAliases() map[string]string {
	return modelAliases
}
