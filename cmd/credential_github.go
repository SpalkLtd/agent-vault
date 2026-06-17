package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/spf13/cobra"
)

var credentialGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Manage GitHub user-to-server credentials (short-lived, human-attributed tokens)",
	Long: `Manage GitHub App user-to-server credentials.

Agent Vault mints short-lived ghu_ access tokens on demand from a rotating
refresh token obtained once via the browser consent flow. Tokens act as the
authorizing human; because a GitHub App is the actor, GitHub records the app
acting on behalf of that user. The agent never sees the client secret or the
refresh token, and the minted token is injection-only (never revealed).

Requires a GitHub App with "Expiring user authorization tokens" enabled
(an OAuth App will not work — it issues no refresh token).`,
}

var credentialGitHubConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect a GitHub App and authorize a user (one-time browser consent)",
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
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		scopes, _ := cmd.Flags().GetString("scopes")
		if clientID == "" {
			return fmt.Errorf("--client-id is required (GitHub App client ID)")
		}
		if clientSecret == "" {
			return fmt.Errorf("--client-secret is required (GitHub App client secret)")
		}

		body, err := json.Marshal(map[string]string{
			"vault":         vault,
			"key":           key,
			"client_id":     clientID,
			"client_secret": clientSecret,
			"scopes":        scopes,
		})
		if err != nil {
			return err
		}
		respBody, err := doAdminRequestWithBody("POST", sess.Address+"/v1/credentials/github/connect", sess.Token, body)
		if err != nil {
			return err
		}
		var result struct {
			AuthorizationURL string `json:"authorization_url"`
		}
		if err := json.Unmarshal(respBody, &result); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		out := cmd.OutOrStdout()
		_, _ = fmt.Fprintf(out, "Open this URL in a browser to authorize GitHub access:\n\n  %s\n\n", result.AuthorizationURL)
		_, _ = fmt.Fprintf(out, "Waiting for authorization to complete (Ctrl-C to stop)...\n")

		// Poll status until connected or timeout.
		statusURL := sess.Address + "/v1/credentials/github/status?vault=" + url.QueryEscape(vault) + "&key=" + url.QueryEscape(key)
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(3 * time.Second)
			sb, err := doAdminRequestWithBody("GET", statusURL, sess.Token, nil)
			if err != nil {
				continue
			}
			var st struct {
				Connected bool   `json:"connected"`
				Identity  string `json:"identity"`
			}
			if err := json.Unmarshal(sb, &st); err != nil {
				continue
			}
			if st.Connected {
				who := st.Identity
				if who == "" {
					who = "(unknown identity)"
				}
				_, _ = fmt.Fprintf(out, "%s Connected GitHub credential %q in vault %q as %s\n", successText("✓"), keyOrDefault(key), vault, who)
				return nil
			}
		}
		return fmt.Errorf("timed out waiting for authorization; re-run `credential github status` once you have authorized in the browser")
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
			Connected             bool   `json:"connected"`
			Identity              string `json:"identity"`
			ConnectedAt           string `json:"connected_at"`
			RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
			LastError             string `json:"last_error"`
		}
		if err := json.Unmarshal(respBody, &st); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}

		out := cmd.OutOrStdout()
		connected := "no"
		if st.Connected {
			connected = "yes"
		}
		_, _ = fmt.Fprintf(out, "Credential:        %s\n", keyOrDefault(key))
		_, _ = fmt.Fprintf(out, "Vault:             %s\n", vault)
		_, _ = fmt.Fprintf(out, "Connected:         %s\n", connected)
		if st.Identity != "" {
			_, _ = fmt.Fprintf(out, "Identity:          %s\n", st.Identity)
		}
		if st.ConnectedAt != "" {
			_, _ = fmt.Fprintf(out, "Connected at:      %s\n", st.ConnectedAt)
		}
		if st.RefreshTokenExpiresAt != "" {
			_, _ = fmt.Fprintf(out, "Refresh expires:   %s\n", st.RefreshTokenExpiresAt)
		}
		if st.LastError != "" {
			_, _ = fmt.Fprintf(out, "Last error:        %s\n", st.LastError)
		}
		return nil
	},
}

// keyOrDefault renders the default GitHub credential key when --key is empty,
// matching the server-side default.
func keyOrDefault(key string) string {
	if key == "" {
		return "GITHUB_TOKEN"
	}
	return key
}

func init() {
	credentialGitHubConnectCmd.Flags().String("key", "", "credential key (default GITHUB_TOKEN)")
	credentialGitHubConnectCmd.Flags().String("client-id", "", "GitHub App client ID")
	credentialGitHubConnectCmd.Flags().String("client-secret", "", "GitHub App client secret")
	credentialGitHubConnectCmd.Flags().String("scopes", "", "comma-separated OAuth scopes (e.g. repo,read:org)")

	credentialGitHubStatusCmd.Flags().String("key", "", "credential key (default GITHUB_TOKEN)")

	credentialGitHubCmd.AddCommand(credentialGitHubConnectCmd)
	credentialGitHubCmd.AddCommand(credentialGitHubStatusCmd)
	credentialCmd.AddCommand(credentialGitHubCmd)
}
