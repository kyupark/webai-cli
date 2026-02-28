package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kyupark/ask/internal/config"
	"github.com/kyupark/ask/internal/provider"
	chatgptpkg "github.com/kyupark/ask/internal/provider/chatgpt"
)

var (
	chatgptModel        string
	chatgptEffort       string
	chatgptResume       bool
	chatgptConversation string
)

var chatgptCmd = &cobra.Command{
	Use:   "chatgpt [question]",
	Short: "ChatGPT commands",
	Long: `Interact with ChatGPT using browser cookies.
  <question>      Ask a question (saves to history)
  ask-incognito  Ask a question (no history)
  list           List recent conversations
	models         Show available models`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return runChatGPTAsk(cmd, args, false)
	},
}

var chatgptAskIncognitoCmd = &cobra.Command{
	Use:   "ask-incognito [question]",
	Short: "Ask ChatGPT (no history)",
	Args:  cobra.MinimumNArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runChatGPTAsk(cmd, args, true) },
}

var chatgptListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent ChatGPT conversations",
	Args:  cobra.NoArgs,
	RunE:  runChatGPTList,
}

var chatgptModelsCmd = &cobra.Command{
	Use:   "models",
	Short: "Show available ChatGPT models (fetches from account if possible)",
	Args:  cobra.NoArgs,
	RunE:  runChatGPTModels,
}

func init() {
	chatgptCmd.Flags().StringVarP(&chatgptModel, "model", "m", "", "Model override (e.g. 'auto', 'gpt-5-2', 'gpt-5-2-thinking')")
	chatgptCmd.Flags().StringVar(&chatgptEffort, "effort", "", "Thinking effort (none, low, medium, high, xhigh)")
	chatgptCmd.Flags().BoolVarP(&chatgptResume, "resume", "r", false, "Resume last conversation")
	chatgptCmd.Flags().StringVar(&chatgptConversation, "conversation", "", "Continue a specific conversation by ID")
	chatgptAskIncognitoCmd.Flags().StringVarP(&chatgptModel, "model", "m", "", "Model override (e.g. 'auto', 'gpt-5-2', 'gpt-5-2-thinking')")
	chatgptAskIncognitoCmd.Flags().StringVar(&chatgptEffort, "effort", "", "Thinking effort (none, low, medium, high, xhigh)")
	chatgptCmd.AddCommand(chatgptAskIncognitoCmd)
	chatgptCmd.AddCommand(chatgptListCmd)
	chatgptCmd.AddCommand(chatgptModelsCmd)
	rootCmd.AddCommand(chatgptCmd)
}

func runChatGPTAsk(cmd *cobra.Command, args []string, temporary bool) error {
	query := strings.Join(args, " ")

	model := globalCfg.ChatGPT.Model
	if chatgptModel != "" {
		model = chatgptModel
	}

	p := chatgptpkg.New(
		globalCfg.ChatGPT.BaseURL,
		model,
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"__Secure-next-auth.session-token": globalCfg.ChatGPT.SessionToken,
		"cf_clearance":                     globalCfg.ChatGPT.CfClearance,
		"_puid":                            globalCfg.ChatGPT.PUID,
	})

	autoLoadCookies(cmd.Context(), p)

	// Apply thinking effort — skip default for debug.
	effort := chatgptEffort
	if effort == "" {
		effort = globalCfg.ChatGPT.Effort
	}
	if effort != "" {
		p.SetThinkingEffort(effort)
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
				fmt.Fprintf(os.Stderr, "[chatgpt] error: %v\n", err)
			}
		},
	}

	if !temporary {
		if chatgptConversation != "" {
			opts.ConversationID = chatgptConversation
		} else if chatgptResume {
			state := config.LoadState()
			if conv := state.GetConversation("chatgpt"); conv != nil {
				opts.ConversationID = conv.ConversationID
				opts.ParentMessageID = conv.ParentMessageID
			} else {
				fmt.Fprintln(os.Stderr, "No previous conversation found for chatgpt — starting new")
			}
		}
	}

	// Save conversation state and capture ID for hint.
	var lastConvID string
	if !temporary {
		opts.OnConversation = func(convID, parentMsgID, respID string) {
			lastConvID = convID
			state := config.LoadState()
			state.SetConversation("chatgpt", &config.ConversationState{
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
		fmt.Fprintf(os.Stderr, "  ask chatgpt -c %s \"follow up\"\n", lastConvID)
	}

	return nil
}

func runChatGPTList(cmd *cobra.Command, args []string) error {
	p := chatgptpkg.New(
		globalCfg.ChatGPT.BaseURL,
		"",
		globalCfg.UserAgent,
		providerTimeout(),
	)

	p.SetCookies(map[string]string{
		"__Secure-next-auth.session-token": globalCfg.ChatGPT.SessionToken,
		"cf_clearance":                     globalCfg.ChatGPT.CfClearance,
		"_puid":                            globalCfg.ChatGPT.PUID,
	})

	return runList(cmd.Context(), p, 20)
}

func runChatGPTModels(cmd *cobra.Command, args []string) error {
	p := chatgptpkg.New(
		globalCfg.ChatGPT.BaseURL,
		"",
		globalCfg.UserAgent,
		providerTimeout(),
	)
	p.SetCookies(map[string]string{
		"__Secure-next-auth.session-token": globalCfg.ChatGPT.SessionToken,
		"cf_clearance":                     globalCfg.ChatGPT.CfClearance,
		"_puid":                            globalCfg.ChatGPT.PUID,
	})
	autoLoadCookies(cmd.Context(), p)

	var logf func(string, ...any)
	if globalCfg.Verbose {
		logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	models, err := p.FetchAvailableModels(cmd.Context(), logf)
	if err == nil && len(models) > 0 {
		fmt.Println("CHATGPT — Available Models (from account)")
		fmt.Println(strings.Repeat("─", 60))
		for _, m := range models {
			fmt.Printf("  %-30s %s\n", m.ID, m.Name)
		}
		fmt.Println()
		return nil
	}

	if err != nil && globalCfg.Verbose {
		fmt.Fprintf(os.Stderr, "[chatgpt] dynamic model fetch failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "[chatgpt] falling back to built-in catalog\n")
	}

	return runModels(p)
}
