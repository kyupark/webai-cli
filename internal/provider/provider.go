// Package provider defines the interface all AI providers must implement.
package provider

import (
	"context"
	"time"
)

// AskOptions configures a single ask invocation.
type AskOptions struct {
	Model     string
	Verbose   bool
	Temporary bool

	// ConversationID continues an existing conversation instead of creating new.
	ConversationID string
	// ParentMessageID is the last message ID for continuation context.
	ParentMessageID string
	// ResponseID is provider-specific continuation context (Gemini).
	ResponseID string

	// OnConversation is called with conversation metadata for state persistence.
	// Called once per Ask invocation with the conversation context.
	OnConversation func(conversationID, parentMessageID, responseID string)

	// OnText is called with incremental text chunks as they arrive.
	OnText func(text string)
	// OnSource is called with citation sources (name, url) when available.
	OnSource func(name, url string)
	// OnError is called for non-fatal errors during streaming.
	OnError func(err error)
	// OnDone is called when the stream completes.
	OnDone func()
	// LogFunc is called for verbose logging.
	LogFunc func(format string, args ...any)
}

// CookieSpec describes which cookies a provider needs from the browser.
type CookieSpec struct {
	// Domain is the domain suffix to match (e.g. "perplexity.ai").
	Domain string
	// Names lists the cookie names to extract.
	Names []string
}

// Provider is the interface each AI backend implements.
type Provider interface {
	// Name returns the provider identifier (e.g. "perplexity").
	Name() string
	// CookieSpecs returns the cookie requirements for auto-extraction.
	CookieSpecs() []CookieSpec
	// SetCookies applies extracted browser cookies to the provider.
	SetCookies(cookies map[string]string)
	// Ask sends a question and streams the response via opts callbacks.
	Ask(ctx context.Context, query string, opts AskOptions) error
}

// Conversation represents a single conversation entry from a provider's history.
type Conversation struct {
	ID        string
	Title     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ListOptions configures a list invocation.
type ListOptions struct {
	Limit   int
	Verbose bool
	LogFunc func(format string, args ...any)
}

type DeleteOptions struct {
	Verbose bool
	LogFunc func(format string, args ...any)
}

// Lister is an optional interface for providers that support listing conversations.
type Lister interface {
	ListConversations(ctx context.Context, opts ListOptions) ([]Conversation, error)
}

type Deleter interface {
	DeleteConversation(ctx context.Context, conversationID string, opts DeleteOptions) error
}

// ModelInfo describes a single model available from a provider.
type ModelInfo struct {
	ID          string   // API identifier (e.g. "gpt-5-2", "claude-opus-4-6")
	Name        string   // Human-friendly name (e.g. "GPT-5.2")
	Description string   // Short description
	Default     bool     // Whether this is the default model
	Tags        []string // e.g. ["reasoning", "fast", "deep-research"]
}

// ModeInfo describes a mode or search focus available from a provider.
type ModeInfo struct {
	ID          string // API identifier (e.g. "reasoning", "deep research")
	Name        string // Human-friendly name
	Description string // Short description
	Default     bool   // Whether this is the default mode
}

// ProviderModels holds the full model/mode catalog for a provider.
type ProviderModels struct {
	Provider    string      // Provider name
	Models      []ModelInfo // Available models
	Modes       []ModeInfo  // Available modes (optional)
	SearchFocus []ModeInfo  // Search focus options (optional, Perplexity)
}

// ModelLister is an optional interface for providers that expose their model catalog.
type ModelLister interface {
	ListModels() ProviderModels
}
