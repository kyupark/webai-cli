package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/qm4/webai-cli/internal/skillbundle"
)

var installOpenClawSkillCmd = &cobra.Command{
	Use:   "install-openclaw-skill",
	Short: "Install bundled OpenClaw skill to ~/.openclaw/workspace/skills/chatmux",
	Args:  cobra.NoArgs,
	RunE:  runInstallOpenClawSkill,
}

func init() {
	rootCmd.AddCommand(installOpenClawSkillCmd)
}

func runInstallOpenClawSkill(cmd *cobra.Command, args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve home directory: %w", err)
	}

	legacyDir := filepath.Join(home, ".openclaw", "workspace", "skills", "webai-cli")
	if _, err := os.Stat(legacyDir); err == nil {
		if err := os.RemoveAll(legacyDir); err != nil {
			return fmt.Errorf("remove legacy skill directory: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Removed legacy OpenClaw skill at %s\n", legacyDir)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("check legacy skill directory: %w", err)
	}

	dstDir := filepath.Join(home, ".openclaw", "workspace", "skills", "chatmux")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create skill directory: %w", err)
	}

	entries, err := fs.ReadDir(skillbundle.Chatmux, "chatmux")
	if err != nil {
		return fmt.Errorf("read embedded skill bundle: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile(skillbundle.Chatmux, filepath.Join("chatmux", entry.Name()))
		if err != nil {
			return fmt.Errorf("read embedded file %s: %w", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, entry.Name()), data, 0o644); err != nil {
			return fmt.Errorf("write skill file %s: %w", entry.Name(), err)
		}
	}

	fmt.Fprintf(os.Stderr, "Installed OpenClaw skill to %s\n", dstDir)
	return nil
}
