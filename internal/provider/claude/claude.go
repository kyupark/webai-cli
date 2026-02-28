// Package claude implements the Claude.ai web API provider.
package claude

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kyupark/ask/internal/httpclient"
	"github.com/kyupark/ask/internal/provider"
)

const (
	defaultBaseURL   = "https://claude.ai"
	orgPath          = "/api/organizations"
	conversationPath = "/api/organizations/%s/chat_conversations"
	completionPath   = "/api/organizations/%s/chat_conversations/%s/completion"

	cookieSessionKey = "sessionKey"
	domainClaude     = "claude.ai"

	defaultModel = "claude-opus-4-6"
)

// --- Request/Response types ---

type orgResponse struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	RateLimitTier string `json:"rate_limit_tier"`
}

type conversationRequest struct {
	Model                          string `json:"model,omitempty"`
	UUID                           string `json:"uuid"`
	Name                           string `json:"name"`
	IncludeConversationPreferences bool   `json:"include_conversation_preferences"`
	PaprikaMode                    string `json:"paprika_mode,omitempty"`
}

type conversationResponse struct {
	UUID string `json:"uuid"`
}

type conversationMessage struct {
	UUID string `json:"uuid"`
}

type conversationDetailResponse struct {
	ChatMessages           []conversationMessage `json:"chat_messages"`
	Messages               []conversationMessage `json:"messages"`
	LatestMessageUUID      string                `json:"latest_message_uuid"`
	CurrentLeafMessageUUID string                `json:"current_leaf_message_uuid"`
}

type completionRequest struct {
	Prompt            string        `json:"prompt"`
	Model             string        `json:"model,omitempty"`
	ParentMessageUUID string        `json:"parent_message_uuid"`
	Timezone          string        `json:"timezone"`
	Attachments       []interface{} `json:"attachments"`
	Files             []interface{} `json:"files"`
	RenderingMode     string        `json:"rendering_mode"`
	Locale            string        `json:"locale,omitempty"`
}

type sseEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index"`
	Message struct {
		ID string `json:"id"`
	} `json:"message"`
	ContentBlock struct {
		Type     string `json:"type"`
		Title    string `json:"title"`
		Name     string `json:"name"`
		Language string `json:"language"`
		Text     string `json:"text"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// conversationListItem represents a conversation in the list response.
type conversationListItem struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// Provider implements the Claude.ai web API backend.
type Provider struct {
	baseURL        string
	model          string
	userAgent      string
	timeout        time.Duration
	sessionKey     string
	thinkingEffort string
	// Cached org ID.
	orgID string
}

// New creates a Claude provider.
func New(baseURL, model, userAgent string, timeout time.Duration) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if model == "" {
		model = defaultModel
	}
	return &Provider{
		baseURL:   baseURL,
		model:     model,
		userAgent: userAgent,
		timeout:   timeout,
	}
}

func (p *Provider) Name() string { return "claude" }

func (p *Provider) CookieSpecs() []provider.CookieSpec {
	return []provider.CookieSpec{
		{Domain: domainClaude, Names: []string{cookieSessionKey}},
	}
}

func (p *Provider) SetCookies(cookies map[string]string) {
	if v := cookies[cookieSessionKey]; v != "" {
		p.sessionKey = v
	}
}

// SetThinkingEffort sets the thinking effort level.
func (p *Provider) SetThinkingEffort(effort string) { p.thinkingEffort = effort }

func (p *Provider) Ask(ctx context.Context, query string, opts provider.AskOptions) error {
	if p.sessionKey == "" {
		return fmt.Errorf("no session cookie — log in to claude.ai in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	model := p.model
	if opts.Model != "" {
		model = opts.Model
	}

	// 1. Get organization ID.
	orgID, err := p.getOrgID(ctx, logf)
	if err != nil {
		return fmt.Errorf("getting org ID: %w", err)
	}

	// 2. Create a new conversation, unless continuing an existing one.
	convID := opts.ConversationID
	if convID == "" {
		convID, err = p.createConversation(ctx, orgID, model, query, logf)
		if err != nil {
			return fmt.Errorf("creating conversation: %w", err)
		}
	}
	logf("[claude] conversation=%s", convID)

	sendOpts := opts
	if convID != "" && sendOpts.ParentMessageID == "" {
		if parentID, parentErr := p.getLatestParentMessageID(ctx, orgID, convID, logf); parentErr == nil {
			sendOpts.ParentMessageID = parentID
		} else {
			logf("[claude] warning: could not resolve parent message UUID: %v", parentErr)
		}
	}

	err = p.sendMessage(ctx, orgID, convID, query, model, sendOpts)

	// 4. Delete conversation if temporary mode.
	if opts.Temporary && opts.ConversationID == "" {
		if delErr := p.deleteConversation(ctx, orgID, convID, logf); delErr != nil {
			logf("[claude] warning: failed to delete conversation: %v", delErr)
		}
	}

	return err
}

func (p *Provider) DeleteConversation(ctx context.Context, conversationID string, opts provider.DeleteOptions) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("conversation ID is required")
	}
	if p.sessionKey == "" {
		return fmt.Errorf("no session cookie — log in to claude.ai in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	orgID, err := p.getOrgID(ctx, logf)
	if err != nil {
		return fmt.Errorf("getting org ID: %w", err)
	}

	return p.deleteConversation(ctx, orgID, conversationID, logf)
}

// ListConversations fetches the user's recent Claude conversations.
func (p *Provider) ListConversations(ctx context.Context, opts provider.ListOptions) ([]provider.Conversation, error) {
	if p.sessionKey == "" {
		return nil, fmt.Errorf("no session cookie — log in to claude.ai in your browser")
	}

	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	orgID, err := p.getOrgID(ctx, logf)
	if err != nil {
		return nil, fmt.Errorf("getting org ID: %w", err)
	}

	url := fmt.Sprintf(p.baseURL+conversationPath+"?limit=%d&starred=false&consistency=eventual", orgID, opts.Limit)
	logf("[claude] GET %s", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	p.setHeaders(req, p.baseURL+"/recents")

	client := httpclient.New(p.timeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var items []conversationListItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding conversations: %w", err)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}
	if len(items) > limit {
		items = items[:limit]
	}

	var conversations []provider.Conversation
	for _, item := range items {
		conv := provider.Conversation{
			ID:    item.UUID,
			Title: item.Name,
		}
		if t, err := time.Parse(time.RFC3339Nano, item.CreatedAt); err == nil {
			conv.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339Nano, item.UpdatedAt); err == nil {
			conv.UpdatedAt = t
		}
		conversations = append(conversations, conv)
	}

	return conversations, nil
}

// --- Internal API methods ---

func (p *Provider) getOrgID(ctx context.Context, logf func(string, ...any)) (string, error) {
	if p.orgID != "" {
		return p.orgID, nil
	}

	url := p.baseURL + orgPath
	logf("[claude] GET %s", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	p.setHeaders(req, p.baseURL+"/new")

	client := httpclient.New(p.timeout)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var orgs []orgResponse
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return "", fmt.Errorf("decoding orgs: %w", err)
	}
	if len(orgs) == 0 {
		return "", fmt.Errorf("no organizations found — ensure you are logged in to claude.ai")
	}

	// Prefer the default personal org.
	for _, org := range orgs {
		if org.RateLimitTier == "default_claude_ai" || org.RateLimitTier == "default_claude_max_20x" {
			p.orgID = org.UUID
			logf("[claude] org=%s (%s)", org.UUID, org.Name)
			return p.orgID, nil
		}
	}

	// Fallback to first org.
	p.orgID = orgs[0].UUID
	logf("[claude] org=%s (%s)", orgs[0].UUID, orgs[0].Name)
	return p.orgID, nil
}

func (p *Provider) createConversation(ctx context.Context, orgID, model, query string, logf func(string, ...any)) (string, error) {
	url := fmt.Sprintf(p.baseURL+conversationPath, orgID)
	logf("[claude] POST %s (model=%s)", url, model)

	reqBody := conversationRequest{
		Model:                          model,
		UUID:                           newUUID(),
		Name:                           conversationTitle(query),
		IncludeConversationPreferences: true,
		PaprikaMode:                    "extended",
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	p.setHeaders(req, p.baseURL+"/new")

	client := httpclient.New(p.timeout)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var conv conversationResponse
	if err := json.NewDecoder(resp.Body).Decode(&conv); err != nil {
		return "", fmt.Errorf("decoding conversation: %w", err)
	}
	if conv.UUID == "" {
		return "", fmt.Errorf("empty conversation UUID in response")
	}

	return conv.UUID, nil
}

func conversationTitle(query string) string {
	title := strings.Join(strings.Fields(strings.TrimSpace(query)), " ")
	if title == "" {
		return "New chat"
	}
	const maxRunes = 120
	r := []rune(title)
	if len(r) <= maxRunes {
		return title
	}
	return string(r[:maxRunes]) + "..."
}

func (p *Provider) getLatestParentMessageID(ctx context.Context, orgID, convID string, logf func(string, ...any)) (string, error) {
	url := fmt.Sprintf(p.baseURL+conversationPath+"/%s", orgID, convID)
	logf("[claude] GET %s", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	p.setHeaders(req, fmt.Sprintf("%s/chat/%s", p.baseURL, convID))

	client := httpclient.New(p.timeout)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var detail conversationDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return "", fmt.Errorf("decoding conversation detail: %w", err)
	}

	if detail.CurrentLeafMessageUUID != "" {
		return detail.CurrentLeafMessageUUID, nil
	}
	if detail.LatestMessageUUID != "" {
		return detail.LatestMessageUUID, nil
	}
	for i := len(detail.ChatMessages) - 1; i >= 0; i-- {
		if detail.ChatMessages[i].UUID != "" {
			return detail.ChatMessages[i].UUID, nil
		}
	}
	for i := len(detail.Messages) - 1; i >= 0; i-- {
		if detail.Messages[i].UUID != "" {
			return detail.Messages[i].UUID, nil
		}
	}

	return "", nil
}

func (p *Provider) sendMessage(ctx context.Context, orgID, convID, query, model string, opts provider.AskOptions) error {
	logf := opts.LogFunc
	if logf == nil {
		logf = func(string, ...any) {}
	}

	url := fmt.Sprintf(p.baseURL+completionPath, orgID, convID)
	logf("[claude] POST %s", url)

	reqBody := completionRequest{
		Prompt:            query,
		Model:             model,
		ParentMessageUUID: "00000000-0000-4000-8000-000000000000",
		Timezone:          "America/Los_Angeles",
		Attachments:       []interface{}{},
		Files:             []interface{}{},
		RenderingMode:     "messages",
	}
	if opts.ParentMessageID != "" {
		reqBody.ParentMessageUUID = opts.ParentMessageID
	}

	// Note: Claude.ai web API does NOT support the thinking field.
	// Extended thinking is only available via the official Messages API.

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	referer := fmt.Sprintf("%s/chat/%s", p.baseURL, convID)
	p.setHeaders(req, referer)
	req.Header.Set("Accept", "text/event-stream, text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	client := httpclient.New(p.timeout)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return p.readStream(resp.Body, convID, opts)
}

func (p *Provider) deleteConversation(ctx context.Context, orgID, convID string, logf func(string, ...any)) error {
	url := fmt.Sprintf(p.baseURL+conversationPath+"/%s", orgID, convID)
	logf("[claude] DELETE %s", url)

	payload, _ := json.Marshal(map[string]string{"uuid": convID})
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	p.setHeaders(req, fmt.Sprintf("%s/chat/%s", p.baseURL, convID))

	client := httpclient.New(p.timeout)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	logf("[claude] conversation deleted")
	return nil
}

func (p *Provider) setHeaders(req *http.Request, referer string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("User-Agent", p.userAgent)
	req.Header.Set("Origin", p.baseURL)
	req.Header.Set("Referer", referer)
	req.Header.Set("Anthropic-Client-Platform", "web_claude_ai")
	req.AddCookie(&http.Cookie{Name: cookieSessionKey, Value: p.sessionKey})
}

func (p *Provider) readStream(r io.Reader, convID string, opts provider.AskOptions) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lastMsgID := ""
	artifactAnnounced := map[int]bool{}

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "" {
			continue
		}

		var event sseEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		if event.Type == "error" && event.Error.Message != "" {
			if opts.OnError != nil {
				opts.OnError(fmt.Errorf("claude: %s", event.Error.Message))
			}
			return fmt.Errorf("claude error: %s", event.Error.Message)
		}

		if event.Delta.Type == "thinking_delta" && event.Delta.Thinking != "" {
			if opts.LogFunc != nil {
				opts.LogFunc("%s", event.Delta.Thinking)
			}
		}
		if event.Delta.Type == "text_delta" && event.Delta.Text != "" {
			if opts.OnText != nil {
				opts.OnText(event.Delta.Text)
			}
		}
		if event.ContentBlock.Type == "artifact" {
			if !artifactAnnounced[event.Index] {
				artifactAnnounced[event.Index] = true
				label := event.ContentBlock.Title
				if label == "" {
					label = event.ContentBlock.Name
				}
				if label == "" {
					label = "artifact"
				}
				if opts.OnText != nil {
					opts.OnText("\n\n[artifact: " + label + "]\n")
				}
			}
			if event.ContentBlock.Text != "" && opts.OnText != nil {
				opts.OnText(event.ContentBlock.Text)
			}
			if event.Delta.PartialJSON != "" && opts.OnText != nil {
				opts.OnText(event.Delta.PartialJSON)
			}
		}
		if event.Type == "message_start" && event.Message.ID != "" {
			lastMsgID = event.Message.ID
		}

		if event.Type == "message_stop" {
			if opts.OnDone != nil {
				opts.OnDone()
			}
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stream: %w", err)
	}

	if opts.OnConversation != nil && convID != "" {
		opts.OnConversation(convID, lastMsgID, "")
	}

	return nil
}

func newUUID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// --- Model catalog ---

// ListModels returns the available Claude.ai models.
func (p *Provider) ListModels() provider.ProviderModels {
	return provider.ProviderModels{
		Provider: "claude",
		Models: []provider.ModelInfo{
			{ID: "claude-opus-4-6", Name: "Claude Opus 4.6", Description: "Smartest — best for complex tasks", Default: true, Tags: []string{"flagship", "reasoning"}},
			{ID: "claude-sonnet-4-6", Name: "Claude Sonnet 4.6", Description: "Best speed/intelligence balance", Default: false, Tags: []string{"balanced"}},
			{ID: "claude-haiku-4-5-20251001", Name: "Claude Haiku 4.5", Description: "Fastest — lightweight tasks", Default: false, Tags: []string{"fast"}},
		},
		Modes: []provider.ModeInfo{
			{ID: "normal", Name: "Normal", Description: "Standard response (no thinking)", Default: false},
			{ID: "low", Name: "Low", Description: "Light thinking (2k budget)", Default: false},
			{ID: "medium", Name: "Medium", Description: "Moderate thinking (8k budget)", Default: false},
			{ID: "high", Name: "High", Description: "Deep thinking (16k budget)", Default: false},
			{ID: "max", Name: "Max", Description: "Maximum thinking (32k budget)", Default: true},
		},
	}
}
