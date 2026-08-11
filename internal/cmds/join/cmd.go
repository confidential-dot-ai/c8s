package join

import (
	"time"

	"github.com/spf13/cobra"
)

// NewReleaseCmd builds the `join-release` subcommand: the in-guest service on
// an rke2 server node that releases the cluster join token to attested
// same-image peers. Baked as a systemd unit in the c8s node image; not run by
// hand in normal operation.
func NewReleaseCmd() *cobra.Command {
	var cfg ReleaseConfig
	cmd := &cobra.Command{
		Use:   "join-release",
		Short: "Release the rke2 agent join token to attested nodes",
		Long: "join-release serves an RA-TLS endpoint that hands the rke2 join\n" +
			"agent token only to an attested node. Without --policy-file, a caller\n" +
			"must be the same measured TDX image (MRTD, RTMR[1], RTMR[2]). With a\n" +
			"policy file, evidence selects a registered native TDX or SNP policy. The token\n" +
			"is a bearer secret: gating it on attestation is what keeps a host\n" +
			"that can read every unmeasured disk from joining a rogue node into\n" +
			"the cluster.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunRelease(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ListenAddr, "listen", ":8444", "HTTPS (RA-TLS) bind address")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (serving-cert quote source and peer-quote verifier)")
	f.StringVar(&cfg.Platform, "platform", "tdx", "TEE platform (the same-image policy is TDX-only)")
	f.StringVar(&cfg.PolicyFile, "policy-file", "", "versioned JSON registry of approved native SNP/TDX node policies (empty keeps legacy same-image TDX mode)")
	f.StringVar(&cfg.TokenPath, "token-path", "/var/lib/rancher/rke2/server/agent-token", "rke2 agent-only join token file (appears once rke2-server has initialised)")
	f.DurationVar(&cfg.VerifyTimeout, "verify-timeout", 10*time.Second, "per-request peer verification timeout")
	return cmd
}

// NewJoinCmd builds the `join` subcommand: the one-shot agent-side client
// that fetches the join token over the mutually attested channel and stages
// it for rke2-agent. Baked as a systemd unit ordered before rke2-agent.
func NewJoinCmd() *cobra.Command {
	var cfg JoinConfig
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Fetch the rke2 join token from an attested server node",
		Long: "join dials a server node's join-release endpoint, verifies the\n" +
			"server's evidence under the legacy same-image TDX policy or a registered\n" +
			"native TDX/SNP policy, presents this node's quote-bound client certificate, and\n" +
			"stages the received token on tmpfs plus an rke2 config drop-in\n" +
			"(server + token-file). One attempt per invocation; retries belong\n" +
			"to the calling unit.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunJoin(cmd.Context(), cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.ServerAddr, "server", "", "join-release endpoint as host:port (required)")
	f.StringVar(&cfg.AttestationAPIURL, "attestation-api-url", "http://127.0.0.1:8400", "local attestation-api base URL (client-cert quote source and server-quote verifier)")
	f.StringVar(&cfg.Platform, "platform", "tdx", "TEE platform (the same-image policy is TDX-only)")
	f.StringVar(&cfg.PolicyFile, "policy-file", "", "versioned JSON registry of approved native SNP/TDX node policies (empty keeps legacy same-image TDX mode)")
	f.StringVar(&cfg.TokenOut, "token-out", "/run/confos/join-token", "where to write the token (rejected unless RAM-backed; never persistent storage)")
	f.StringVar(&cfg.FragmentOut, "fragment-out", "/etc/rancher/rke2/config.yaml.d/50-join.yaml", "rke2 config drop-in to write")
	f.IntVar(&cfg.SupervisorPort, "supervisor-port", 9345, "rke2 supervisor port on the server node (fragment server URL)")
	f.DurationVar(&cfg.Timeout, "timeout", 30*time.Second, "per-step network timeout")
	_ = cmd.MarkFlagRequired("server")
	return cmd
}
