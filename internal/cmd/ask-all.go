package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kyupark/ask/internal/config"
	"github.com/spf13/cobra"

	"github.com/kyupark/ask/internal/provider"
	"github.com/kyupark/ask/internal/provider/chatgpt"
	"github.com/kyupark/ask/internal/provider/claude"
	"github.com/kyupark/ask/internal/provider/gemini"
	"github.com/kyupark/ask/internal/provider/grok"
	"github.com/kyupark/ask/internal/provider/perplexity"
)

var askAllCmd = &cobra.Command{
	Use:   "all [question]",
	Short: "Ask all providers at once",
	Long: `Ask all five AI providers simultaneously and display results as they arrive.
Runs in standard mode by default.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runAskAll,
}

var askAllResume bool
var askAllConversationID string

func init() {
	askAllCmd.Flags().BoolVarP(&askAllResume, "resume-all", "r", false, "Continue the last all conversation state for each provider")
	askAllCmd.Flags().StringVarP(&askAllConversationID, "conversation", "c", "", "Continue a specific all conversation ID")
	rootCmd.AddCommand(askAllCmd)
}

// providerResult holds the buffered output from a single provider.
type providerResult struct {
	name            string
	model           string
	output          string
	err             error
	conversationID  string
	parentMessageID string
	responseID      string
}

func runAskAll(cmd *cobra.Command, args []string) error {
	query := strings.Join(args, " ")
	timeout := providerTimeout()

	type entry struct {
		p     provider.Provider
		model string
	}
	entries := []entry{
		{newChatGPTProvider(), askAllChatGPTModel()},
		{newClaudeProvider(), askAllClaudeModel()},
		{newGeminiProvider(), askAllGeminiModel()},
		{newGrokProvider(), askAllGrokModel()},
		{newPerplexityProvider(), askAllPerplexityModel()},
	}
	state := config.LoadState()

	resumeByProvider := make(map[string]*config.ConversationState)
	if askAllConversationID != "" {
		bundle := state.GetAskAllConversation(askAllConversationID)
		if bundle == nil || len(bundle.Providers) == 0 {
			return fmt.Errorf("all conversation not found: %s", askAllConversationID)
		}
		for k, v := range bundle.Providers {
			if v != nil {
				resumeByProvider[k] = v
			}
		}
	} else if askAllResume {
		if state.LastAskAllID != "" {
			if bundle := state.GetAskAllConversation(state.LastAskAllID); bundle != nil {
				for k, v := range bundle.Providers {
					if v != nil {
						resumeByProvider[k] = v
					}
				}
			}
		}
		if len(resumeByProvider) == 0 {
			for _, e := range entries {
				if conv := state.GetConversation(e.p.Name()); conv != nil {
					resumeByProvider[e.p.Name()] = conv
				}
			}
		}
	}

	// Load cookies for all providers in parallel.
	var wgCookies sync.WaitGroup
	for _, e := range entries {
		wgCookies.Add(1)
		go func(p provider.Provider) {
			defer wgCookies.Done()
			autoLoadCookies(cmd.Context(), p)
		}(e.p)
	}
	wgCookies.Wait()

	// Fan out: ask all providers in parallel, buffer responses.
	results := make(chan providerResult, len(entries))
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	for _, e := range entries {
		go func(p provider.Provider, model string) {
			var buf bytes.Buffer
			var lastConversationID string
			var lastParentMessageID string
			var lastResponseID string
			opts := provider.AskOptions{
				Model:     model,
				Verbose:   globalCfg.Verbose,
				Temporary: false,
				OnConversation: func(conversationID, parentMessageID, responseID string) {
					lastConversationID = conversationID
					lastParentMessageID = parentMessageID
					lastResponseID = responseID
				},
				OnText: func(text string) {
					buf.WriteString(text)
				},
				OnError: func(err error) {
					if globalCfg.Verbose {
						fmt.Fprintf(os.Stderr, "[%s] error: %v\n", p.Name(), err)
					}
				},
			}
			if globalCfg.Verbose {
				opts.LogFunc = func(format string, args ...any) {
					fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Name(), fmt.Sprintf(format, args...))
				}
			}
			if conv := resumeByProvider[p.Name()]; conv != nil {
				opts.ConversationID = conv.ConversationID
				opts.ParentMessageID = conv.ParentMessageID
				opts.ResponseID = conv.ResponseID
			}
			err := p.Ask(ctx, query, opts)
			if err != nil && p.Name() == "grok" {
				if globalCfg.Verbose {
					fmt.Fprintf(os.Stderr, "[%s] retrying once after error: %v\n", p.Name(), err)
				}
				buf.Reset()
				select {
				case <-ctx.Done():
					err = ctx.Err()
				default:
					time.Sleep(400 * time.Millisecond)
					err = p.Ask(ctx, query, opts)
				}
			}

			if err != nil && strings.TrimSpace(buf.String()) != "" {
				if globalCfg.Verbose {
					fmt.Fprintf(os.Stderr, "[%s] ignoring trailing error after response: %v\n", p.Name(), err)
				}
				err = nil
			}
			results <- providerResult{
				name:            p.Name(),
				model:           model,
				output:          buf.String(),
				err:             err,
				conversationID:  lastConversationID,
				parentMessageID: lastParentMessageID,
				responseID:      lastResponseID,
			}
		}(e.p, e.model)
	}

	updatedState := false
	bundleProviders := make(map[string]*config.ConversationState)

	// Print results as they arrive.
	for i := 0; i < len(entries); i++ {
		r := <-results
		if i > 0 {
			fmt.Println()
		}
		if r.model != "" {
			fmt.Printf("━━━ %s (%s) ━━━\n\n", r.name, r.model)
		} else {
			fmt.Printf("━━━ %s ━━━\n\n", r.name)
		}
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "  error: %v\n", r.err)
		} else {
			fmt.Println(strings.TrimRight(r.output, "\n"))
		}

		if r.conversationID != "" {
			cs := &config.ConversationState{
				ConversationID:  r.conversationID,
				ParentMessageID: r.parentMessageID,
				ResponseID:      r.responseID,
			}
			state.SetConversation(r.name, cs)
			bundleProviders[r.name] = cs
			updatedState = true
			fmt.Printf("\nConversation: %s\n", r.conversationID)
		}
	}

	if updatedState {
		askAllID := fmt.Sprintf("aa_%d", time.Now().UnixNano())
		state.SetAskAllConversation(askAllID, bundleProviders)
		_ = config.SaveState(state)
		fmt.Printf("\nAll conversation: %s\n", askAllID)
		fmt.Printf("  ask all -c %s \"follow up\"\n", askAllID)
		fmt.Println("  ask all -c <id> \"follow up\"")
	}

	return nil
}

func askAllChatGPTModel() string {
	if model := strings.TrimSpace(globalCfg.ChatGPT.Model); model != "" {
		return model
	}
	return "gpt-5-2"
}

func askAllClaudeModel() string {
	if model := strings.TrimSpace(globalCfg.Claude.Model); model != "" {
		return model
	}
	return "claude-opus-4-6"
}

func askAllGeminiModel() string {
	if model := strings.TrimSpace(globalCfg.Gemini.Model); model != "" {
		return model
	}
	return "gemini-3-pro"
}

func askAllGrokModel() string {
	return grok.ResolveModel(strings.TrimSpace(globalCfg.Grok.Model))
}

func askAllPerplexityModel() string {
	if model := strings.TrimSpace(globalCfg.Perplexity.Model); model != "" {
		return model
	}
	return "pplx_reasoning"
}

func newPerplexityProvider() provider.Provider {
	p := perplexity.New(
		globalCfg.Perplexity.BaseURL,
		globalCfg.UserAgent,
		providerTimeout(),
	)
	p.SetCookies(map[string]string{
		"cf_clearance":                     globalCfg.Perplexity.CfClearance,
		"__Secure-next-auth.session-token": globalCfg.Perplexity.SessionCookie,
	})
	if mode := globalCfg.Perplexity.Mode; mode != "" {
		p.SetMode(mode)
	}
	if focus := globalCfg.Perplexity.SearchFocus; focus != "" {
		p.SetSearchFocus(focus)
	}
	return p
}

func newChatGPTProvider() provider.Provider {
	p := chatgpt.New(
		globalCfg.ChatGPT.BaseURL,
		globalCfg.ChatGPT.Model,
		globalCfg.UserAgent,
		providerTimeout(),
	)
	p.SetCookies(map[string]string{
		"__Secure-next-auth.session-token": globalCfg.ChatGPT.SessionToken,
		"cf_clearance":                     globalCfg.ChatGPT.CfClearance,
		"_puid":                            globalCfg.ChatGPT.PUID,
	})
	if effort := globalCfg.ChatGPT.Effort; effort != "" {
		p.SetThinkingEffort(effort)
	}
	return p
}

func newGeminiProvider() provider.Provider {
	p := gemini.New(
		globalCfg.UserAgent,
		providerTimeout(),
	)
	p.SetCookies(map[string]string{
		"__Secure-1PSID":   globalCfg.Gemini.PSID,
		"__Secure-1PSIDTS": globalCfg.Gemini.PSIDTS,
		"__Secure-1PSIDCC": globalCfg.Gemini.PSIDCC,
	})
	return p
}

func newGrokProvider() provider.Provider {
	p := grok.New(
		globalCfg.UserAgent,
		providerTimeout(),
	)
	p.SetCookies(map[string]string{
		"auth_token": globalCfg.Grok.AuthToken,
		"ct0":        globalCfg.Grok.CT0,
	})
	if globalCfg.Grok.DeepSearch {
		p.SetDeepSearch(true)
	}
	if globalCfg.Grok.Reasoning {
		p.SetReasoning(true)
	}
	return p
}

func newClaudeProvider() provider.Provider {
	model := globalCfg.Claude.Model
	if model == "" {
		model = "claude-sonnet-4-6"
	}

	p := claude.New(
		globalCfg.Claude.BaseURL,
		model,
		globalCfg.UserAgent,
		providerTimeout(),
	)
	p.SetCookies(map[string]string{
		"sessionKey": globalCfg.Claude.SessionKey,
	})
	if effort := globalCfg.Claude.Effort; effort != "" {
		p.SetThinkingEffort(effort)
	}
	return p
}
