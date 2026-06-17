package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var credentialGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Manage GitHub App installation credentials (short-lived, app-attributed tokens)",
	Long: `Manage GitHub App INSTALLATION credentials (server-to-server).

Agent Vault mints short-lived ghs_ installation access tokens on demand by
signing a JWT with the App private key — no browser flow, no refresh token. The
token acts as the App/bot: it is gated by the App's own permissions and ruleset
bypass membership, independent of any human, and actions are attributed to the
App. The agent never sees the private key, and the minted token is injection-only
(never revealed).`,
}

var credentialGitHubConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect a GitHub App installation (App id + installation id + private key)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}
		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}
		key, _ := cmd.Flags().GetString("key")
		appID, _ := cmd.Flags().GetString("app-id")
		instID, _ := cmd.Flags().GetString("installation-id")
		pkFile, _ := cmd.Flags().GetString("private-key-file")
		perms, _ := cmd.Flags().GetString("permissions")
		repos, _ := cmd.Flags().GetString("repositories")
		if appID == "" {
			return fmt.Errorf("--app-id is required (GitHub App id or client id)")
		}
		if instID == "" {
			return fmt.Errorf("--installation-id is required")
		}
		if pkFile == "" {
			return fmt.Errorf("--private-key-file is required (path to the App private key .pem)")
		}
		pem, err := os.ReadFile(pkFile)
		if err != nil {
			return fmt.Errorf("reading private key file: %w", err)
		}

		body, err := json.Marshal(map[string]string{
			"vault":           vault,
			"key":             key,
			"app_id":          appID,
			"installation_id": instID,
			"private_key":     string(pem),
			"permissions":     perms,
			"repositories":    repos,
		})
		if err != nil {
			return err
		}
		respBody, err := doAdminRequestWithBody("POST", sess.Address+"/v1/credentials/github/connect", sess.Token, body)
		if err != nil {
			return err
		}
		var result struct {
			Connected bool   `json:"connected"`
			Identity  string `json:"identity"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		who := result.Identity
		if who == "" {
			who = "(unknown app)"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Connected GitHub credential %q in vault %q as %s\n",
			successText("✓"), githubKeyOrDefault(key), vault, who)
		return nil
	},
}

var credentialGitHubStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show connection status for a GitHub credential",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sess, tokenSource, err := resolveSession()
		if err != nil {
			return err
		}
		vault, err := resolveVaultForCommand(cmd, tokenSource)
		if err != nil {
			return err
		}
		key, _ := cmd.Flags().GetString("key")

		statusURL := sess.Address + "/v1/credentials/github/status?vault=" + url.QueryEscape(vault) + "&key=" + url.QueryEscape(key)
		respBody, err := doAdminRequestWithBody("GET", statusURL, sess.Token, nil)
		if err != nil {
			return err
		}
		var st struct {
			Connected      bool   `json:"connected"`
			Identity       string `json:"identity"`
			AppID          string `json:"app_id"`
			InstallationID string `json:"installation_id"`
			ConnectedAt    string `json:"connected_at"`
			LastMintAt     string `json:"last_mint_at"`
			LastError      string `json:"last_error"`
		}
		if err := json.Unmarshal(respBody, &st); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		out := cmd.OutOrStdout()
		connected := "no"
		if st.Connected {
			connected = "yes"
		}
		_, _ = fmt.Fprintf(out, "Credential:        %s\n", githubKeyOrDefault(key))
		_, _ = fmt.Fprintf(out, "Vault:             %s\n", vault)
		_, _ = fmt.Fprintf(out, "Connected:         %s\n", connected)
		if st.Identity != "" {
			_, _ = fmt.Fprintf(out, "Identity:          %s\n", st.Identity)
		}
		if st.AppID != "" {
			_, _ = fmt.Fprintf(out, "App id:            %s\n", st.AppID)
		}
		if st.InstallationID != "" {
			_, _ = fmt.Fprintf(out, "Installation id:   %s\n", st.InstallationID)
		}
		if st.ConnectedAt != "" {
			_, _ = fmt.Fprintf(out, "Connected at:      %s\n", st.ConnectedAt)
		}
		if st.LastError != "" {
			_, _ = fmt.Fprintf(out, "Last error:        %s\n", st.LastError)
		}
		return nil
	},
}

// githubKeyOrDefault renders the default GitHub credential key when --key is
// empty, matching the server-side default.
func githubKeyOrDefault(key string) string {
	if key == "" {
		return "GITHUB"
	}
	return key
}

func init() {
	credentialGitHubConnectCmd.Flags().String("key", "", "credential key (default GITHUB)")
	credentialGitHubConnectCmd.Flags().String("app-id", "", "GitHub App id or client id (JWT issuer)")
	credentialGitHubConnectCmd.Flags().String("installation-id", "", "installation id the token is minted for")
	credentialGitHubConnectCmd.Flags().String("private-key-file", "", "path to the GitHub App private key .pem")
	credentialGitHubConnectCmd.Flags().String("permissions", "", "optional JSON permission subset, e.g. {\"contents\":\"write\"}")
	credentialGitHubConnectCmd.Flags().String("repositories", "", "optional comma-separated repo names to scope the token to")

	credentialGitHubStatusCmd.Flags().String("key", "", "credential key (default GITHUB)")

	credentialGitHubCmd.AddCommand(credentialGitHubConnectCmd)
	credentialGitHubCmd.AddCommand(credentialGitHubStatusCmd)
	credentialCmd.AddCommand(credentialGitHubCmd)
}
