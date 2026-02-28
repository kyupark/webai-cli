package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/kyupark/ask/internal/config"
	"github.com/kyupark/ask/internal/provider"
)

func runDelete(ctx context.Context, p provider.Provider, conversationID string) error {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return fmt.Errorf("conversation ID is required")
	}

	deleter, ok := p.(provider.Deleter)
	if !ok {
		return fmt.Errorf("%s does not support deleting conversations", p.Name())
	}

	autoLoadCookies(ctx, p)

	opts := provider.DeleteOptions{Verbose: globalCfg.Verbose}
	if globalCfg.Verbose {
		opts.LogFunc = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Name(), fmt.Sprintf(format, args...))
		}
	}

	if err := deleter.DeleteConversation(ctx, conversationID, opts); err != nil {
		return err
	}

	clearConversationState(p.Name(), conversationID)
	fmt.Printf("Deleted conversation: %s\n", conversationID)
	return nil
}

func clearConversationState(providerName, conversationID string) {
	state := config.LoadState()
	changed := false
	deleteAll := providerName == "grok" && strings.EqualFold(strings.TrimSpace(conversationID), "all")

	if conv := state.GetConversation(providerName); conv != nil && (deleteAll || conv.ConversationID == conversationID) {
		delete(state.LastConversation, providerName)
		changed = true
	}

	for id, bundle := range state.AskAll {
		if bundle == nil || bundle.Providers == nil {
			continue
		}
		conv := bundle.Providers[providerName]
		if conv != nil && (deleteAll || conv.ConversationID == conversationID) {
			delete(state.AskAll, id)
			if state.LastAskAllID == id {
				state.LastAskAllID = ""
			}
			changed = true
		}
	}

	if changed {
		_ = config.SaveState(state)
	}
}
