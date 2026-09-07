package allowlist

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newUploadCmd(o *options) *cobra.Command {
	var (
		dryRun   bool
		force    bool
		strict   bool
		required []string
	)
	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Replace the entire allowlist with the contents of a file",
		Long: `Atomically replace the entire allowlist with the contents of <file> (the
canonical JSON 'export' writes). CDS assigns the new version.

If none of the file's image labels name a core c8s component (` + fmt.Sprintf("%v", defaultRequiredComponents) + `),
upload refuses unless --force, since a cluster missing them cannot pull its own
control plane. Override the required set with --require. The file is lint-checked
before upload; --strict makes lint warnings fatal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}

			findings := lintOffline(desired)
			for _, f := range findings {
				fmt.Fprintf(cmd.ErrOrStderr(), "lint: %s\n", f)
			}
			// An error means the document cannot do what it says, so --force
			// does not reach it: that flag is about missing components.
			if errs := countErrors(findings); errs > 0 {
				return fmt.Errorf("refusing to upload: %d lint error(s)", errs)
			}
			if strict && len(findings) > 0 {
				return fmt.Errorf("refusing to upload: %d lint warning(s) with --strict", len(findings))
			}

			reqComponents := defaultRequiredComponents
			if len(required) > 0 {
				// An empty needle matches every ref and would silently disable the
				// guard; reject it (and a bare wildcard) outright.
				for _, r := range required {
					if _, err := requireLabel(r, "--require value"); err != nil {
						return err
					}
				}
				reqComponents = required
			}
			if missing := missingComponents(uploadImageLabels(desired), reqComponents); len(missing) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: uploaded allowlist is missing core c8s component(s): %v\n", missing)
				if !force {
					return fmt.Errorf("refusing to upload an allowlist missing core components %v; re-run with --force if this is intentional", missing)
				}
				fmt.Fprintln(cmd.ErrOrStderr(), "proceeding anyway (--force)")
			}

			c, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}

			// Show the operator what will change before writing.
			if live, _, err := c.List(ctx(cmd)); err == nil {
				_ = printDiff(cmd.OutOrStdout(), o.output, diffAllowlists(live, desired))
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not fetch current allowlist for diff: %v\n", err)
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "dry-run: would replace allowlist with %d workload(s)\n", len(desired.Workloads))
				return nil
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			if err := c.ReplaceAll(ctx(cmd), desired, signer); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "uploaded %d workload(s)\n", len(desired.Workloads))
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the diff without replacing the allowlist")
	cmd.Flags().BoolVar(&force, "force", false, "upload even if core c8s components are missing")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat lint warnings as fatal")
	cmd.Flags().StringSliceVar(&required, "require", nil, "component identifiers that must appear in the uploaded image refs (overrides the default set)")
	return cmd
}

// requireLabel rejects an empty or bare-wildcard label. Image and name labels
// are informational, but "" or "*" almost always signals a mistake and a
// wildcard must never be mistaken for a policy value.
func requireLabel(val, what string) (string, error) {
	switch val {
	case "":
		return "", fmt.Errorf("%s must not be empty", what)
	case "*":
		return "", fmt.Errorf("%s must not be a bare wildcard %q", what, val)
	}
	return val, nil
}
