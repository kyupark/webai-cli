package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kyupark/ask/internal/skillbundle"
)

var installOpenClawSkillCmd = &cobra.Command{
	Use:   "install-openclaw-skill",
	Short: "Install bundled OpenClaw skill to ~/.openclaw/workspace/skills/ask",
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

	legacyDirs := []string{
		filepath.Join(home, ".openclaw", "workspace", "skills", "webai-cli"),
		filepath.Join(home, ".openclaw", "workspace", "skills", "chatmux"),
	}
	for _, legacyDir := range legacyDirs {
		if _, err := os.Stat(legacyDir); err == nil {
			if err := os.RemoveAll(legacyDir); err != nil {
				return fmt.Errorf("remove legacy skill directory %s: %w", legacyDir, err)
			}
			fmt.Fprintf(os.Stderr, "Removed legacy OpenClaw skill at %s\n", legacyDir)
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("check legacy skill directory %s: %w", legacyDir, err)
		}
	}

	dstDir := filepath.Join(home, ".openclaw", "workspace", "skills", "ask")
	if err := os.RemoveAll(dstDir); err != nil {
		return fmt.Errorf("reset skill directory: %w", err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create skill directory: %w", err)
	}

	entries, err := fs.ReadDir(skillbundle.Ask, "ask")
	if err != nil {
		return fmt.Errorf("read embedded skill bundle: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := fs.ReadFile(skillbundle.Ask, filepath.Join("ask", entry.Name()))
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
