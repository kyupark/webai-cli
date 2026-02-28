package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kyupark/ask/internal/config"
	"github.com/kyupark/ask/internal/provider"
	claudepkg "github.com/kyupark/ask/internal/provider/claude"
)

var (
	claudeModel          string
	claudeThinkingEffort string
	claudeResume         bool
	claudeConversation   string
)

var claudeCmd = &cobra.Command{
	Use:   "claude [question]",
	Short: "Claude.ai commands",
	Long: `Interact with Claude.ai using browser cookies.
  <question>      Ask a question (saves to history)
  ask-incognito  Ask a question (no history)
  list           List recent conversations
	delete         Delete a conversation by ID
	models         Show available models and modes`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return runClaudeAsk(cmd, args, false)
	},
}

var claudeAskIncognitoCmd = &cobra.Command{
	Use:   "ask-incognito [question]",
	Short: "Ask Claude (no history)",
	Args:  cobra.MinimumNArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runClaudeAsk(cmd, args, true) },
}

var claudeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent Claude conversations",
	Args:  cobra.NoArgs,
	RunE:  runClaudeList,
}

var claudeDeleteCmd = &cobra.Command{
	Use:   "delete <conversation-id>",
	Short: "Delete a Claude conversation",
	Args:  cobra.ExactArgs(1),
	RunE:  runClaudeDelete,
}

var claudeModelsCmd = &cobra.Command{
	Use:   "models",
	Short: "Show available Claude models and modes",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		p := claudepkg.New("", "", "", providerTimeout())
		return runModels(p)
	},
}

func init() {
	claudeCmd.Flags().StringVarP(&claudeModel, "model", "m", "", "Model override (e.g. 'claude-opus-4-6', 'claude-sonnet-4-6')")
	claudeCmd.Flags().StringVar(&claudeThinkingEffort, "effort", "", "Thinking effort (low, medium, high, max)")
	claudeCmd.Flags().BoolVarP(&claudeResume, "resume", "r", false, "Resume last conversation")
	claudeCmd.Flags().StringVar(&claudeConversation, "conversation", "", "Continue a specific conversation by ID")
	claudeAskIncognitoCmd.Flags().StringVarP(&claudeModel, "model", "m", "", "Model override (e.g. 'claude-opus-4-6', 'claude-sonnet-4-6')")
	claudeAskIncognitoCmd.Flags().StringVar(&claudeThinkingEffort, "effort", "", "Thinking effort (low, medium, high, max)")
	claudeCmd.AddCommand(claudeAskIncognitoCmd)
	claudeCmd.AddCommand(claudeListCmd)
	claudeCmd.AddCommand(claudeDeleteCmd)
	claudeCmd.AddCommand(claudeModelsCmd)
	rootCmd.AddCommand(claudeCmd)
}

func runClaudeAsk(cmd *cobra.Command, args []string, temporary bool) error {
	query := strings.Join(args, " ")

	p := claudepkg.New(
		globalCfg.Claude.BaseURL,
		"",
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"sessionKey": globalCfg.Claude.SessionKey,
	})

	autoLoadCookies(cmd.Context(), p)

	effort := claudeThinkingEffort
	if effort == "" {
		effort = globalCfg.Claude.Effort
	}
	if effort == "" {
		effort = "medium"
	}
	p.SetThinkingEffort(effort)
	model := globalCfg.Claude.Model
	if claudeModel != "" {
		model = claudeModel
	}

	opts := provider.AskOptions{
		Model:     model,
		Verbose:   globalCfg.Verbose,
		Temporary: temporary,
		OnText: func(text string) {
			fmt.Print(text)
		},
		OnError: func(err error) {
			if globalCfg.Verbose {
				fmt.Fprintf(os.Stderr, "[claude] error: %v\n", err)
			}
		},
	}

	if !temporary {
		if claudeConversation != "" {
			opts.ConversationID = claudeConversation
		} else if claudeResume {
			state := config.LoadState()
			if conv := state.GetConversation("claude"); conv != nil {
				opts.ConversationID = conv.ConversationID
				opts.ParentMessageID = conv.ParentMessageID
			} else {
				fmt.Fprintln(os.Stderr, "No previous conversation found for claude — starting new")
			}
		}
	}

	// Save conversation state and capture ID for hint.
	var lastConvID string
	if !temporary {
		opts.OnConversation = func(convID, parentMsgID, respID string) {
			lastConvID = convID
			state := config.LoadState()
			state.SetConversation("claude", &config.ConversationState{
				ConversationID:  convID,
				ParentMessageID: parentMsgID,
			})
			_ = config.SaveState(state)
		}
	}
	if globalCfg.Verbose {
		opts.LogFunc = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	if err := p.Ask(cmd.Context(), query, opts); err != nil {
		return err
	}

	fmt.Println()

	if lastConvID != "" && !temporary {
		fmt.Fprintf(os.Stderr, "\nConversation: %s\n", lastConvID)
		fmt.Fprintf(os.Stderr, "  ask claude -c %s \"follow up\"\n", lastConvID)
	}

	return nil
}

func runClaudeList(cmd *cobra.Command, args []string) error {
	p := claudepkg.New(
		globalCfg.Claude.BaseURL,
		"",
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"sessionKey": globalCfg.Claude.SessionKey,
	})

	return runList(cmd.Context(), p, 20)
}

func runClaudeDelete(cmd *cobra.Command, args []string) error {
	p := claudepkg.New(
		globalCfg.Claude.BaseURL,
		"",
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"sessionKey": globalCfg.Claude.SessionKey,
	})

	return runDelete(cmd.Context(), p, args[0])
}
