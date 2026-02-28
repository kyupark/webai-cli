package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kyupark/ask/internal/config"
	"github.com/kyupark/ask/internal/provider"
	geminipkg "github.com/kyupark/ask/internal/provider/gemini"
)

var (
	geminiModel        string
	geminiResume       bool
	geminiConversation string
)

var geminiCmd = &cobra.Command{
	Use:   "gemini [question]",
	Short: "Google Gemini commands",
	Long: `Interact with Google Gemini using browser cookies.
  <question>      Ask a question (saves to history)
  ask-incognito  Ask a question (no history)
  list           List recent conversations
	delete         Delete a conversation by ID
	models         Show available models`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return runGeminiAsk(cmd, args, false)
	},
}

var geminiAskIncognitoCmd = &cobra.Command{
	Use:   "ask-incognito [question]",
	Short: "Ask Gemini (no history)",
	Args:  cobra.MinimumNArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runGeminiAsk(cmd, args, true) },
}

var geminiListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent Gemini conversations",
	Args:  cobra.NoArgs,
	RunE:  runGeminiList,
}

var geminiDeleteCmd = &cobra.Command{
	Use:   "delete <conversation-id>",
	Short: "Delete a Gemini conversation",
	Args:  cobra.ExactArgs(1),
	RunE:  runGeminiDelete,
}

var geminiModelsCmd = &cobra.Command{
	Use:   "models",
	Short: "Show available Gemini models",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		p := geminipkg.New("", providerTimeout())
		return runModels(p)
	},
}

func init() {
	geminiCmd.Flags().StringVarP(&geminiModel, "model", "m", "", "Model (e.g. 'gemini-3-pro', 'gemini-3-flash', 'gemini-deep-research')")
	geminiCmd.Flags().BoolVarP(&geminiResume, "resume", "r", false, "Resume last conversation")
	geminiCmd.Flags().StringVar(&geminiConversation, "conversation", "", "Continue a specific conversation by ID")
	geminiAskIncognitoCmd.Flags().StringVarP(&geminiModel, "model", "m", "", "Model (e.g. 'gemini-3-pro', 'gemini-3-flash', 'gemini-deep-research')")
	geminiCmd.AddCommand(geminiAskIncognitoCmd)
	geminiCmd.AddCommand(geminiListCmd)
	geminiCmd.AddCommand(geminiDeleteCmd)
	geminiCmd.AddCommand(geminiModelsCmd)
	rootCmd.AddCommand(geminiCmd)
}

func runGeminiAsk(cmd *cobra.Command, args []string, temporary bool) error {
	query := strings.Join(args, " ")

	model := geminiModel
	if model == "" {
		model = globalCfg.Gemini.Model
	}

	p := geminipkg.New(
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"__Secure-1PSID":   globalCfg.Gemini.PSID,
		"__Secure-1PSIDTS": globalCfg.Gemini.PSIDTS,
		"__Secure-1PSIDCC": globalCfg.Gemini.PSIDCC,
	})

	autoLoadCookies(cmd.Context(), p)

	opts := provider.AskOptions{
		Model:     model,
		Verbose:   globalCfg.Verbose,
		Temporary: temporary,
		OnText: func(text string) {
			fmt.Print(text)
		},
		OnError: func(err error) {
			if globalCfg.Verbose {
				fmt.Fprintf(os.Stderr, "[gemini] error: %v\n", err)
			}
		},
	}

	if !temporary {
		if geminiConversation != "" {
			opts.ConversationID = geminiConversation
		} else if geminiResume {
			state := config.LoadState()
			if conv := state.GetConversation("gemini"); conv != nil {
				opts.ConversationID = conv.ConversationID
				opts.ResponseID = conv.ResponseID
			} else {
				fmt.Fprintln(os.Stderr, "No previous conversation found for gemini — starting new")
			}
		}
	}

	// Save conversation state and capture ID for hint.
	var lastConvID string
	if !temporary {
		opts.OnConversation = func(convID, parentMsgID, respID string) {
			lastConvID = convID
			state := config.LoadState()
			state.SetConversation("gemini", &config.ConversationState{
				ConversationID: convID,
				ResponseID:     respID,
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
		fmt.Fprintf(os.Stderr, "  ask gemini -c %s \"follow up\"\n", lastConvID)
	}

	return nil
}

func runGeminiList(cmd *cobra.Command, args []string) error {
	p := geminipkg.New(
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"__Secure-1PSID":   globalCfg.Gemini.PSID,
		"__Secure-1PSIDTS": globalCfg.Gemini.PSIDTS,
		"__Secure-1PSIDCC": globalCfg.Gemini.PSIDCC,
	})

	return runList(cmd.Context(), p, 20)
}

func runGeminiDelete(cmd *cobra.Command, args []string) error {
	p := geminipkg.New(
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"__Secure-1PSID":   globalCfg.Gemini.PSID,
		"__Secure-1PSIDTS": globalCfg.Gemini.PSIDTS,
		"__Secure-1PSIDCC": globalCfg.Gemini.PSIDCC,
	})

	return runDelete(cmd.Context(), p, args[0])
}
