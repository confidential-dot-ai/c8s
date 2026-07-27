package secrets

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newPutCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "put <entry> <path> <value|@file|->",
		Short: "Deposit a secret for a workload entry",
		Long: `Deposit a secret the CDS broker may release to workloads attested as
the given entry. The value is read from the argument, an @file, or stdin (-),
and is wrapped to the broker encryption key before it leaves this CLI.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			entry, path := args[0], args[1]
			value, err := readValueArg(args[2])
			if err != nil {
				return fmt.Errorf("read value: %w", err)
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			hc, err := o.httpClient(ctx(cmd))
			if err != nil {
				return err
			}
			bc, err := o.brokerIdentity(ctx(cmd), hc)
			if err != nil {
				return err
			}
			if err := bc.put(ctx(cmd), entry, path, value, signer); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "deposited %s %s (%d bytes)\n", entry, path, len(value))
			return nil
		},
	}
	return cmd
}

func newGetCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <entry> <path>",
		Short: "Read back a deposited secret",
		Long: `Read back a secret from the broker store. The raw value is written to
stdout; use -o json for base64. This is an operator debugging path — workloads
receive secrets through the attested fetch flow, not this endpoint.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			hc, err := o.httpClient(ctx(cmd))
			if err != nil {
				return err
			}
			bc, err := o.brokerIdentity(ctx(cmd), hc)
			if err != nil {
				return err
			}
			value, err := bc.get(ctx(cmd), args[0], args[1], signer)
			if err != nil {
				return err
			}
			if o.output == "json" {
				fmt.Println(base64.StdEncoding.EncodeToString(value))
				return nil
			}
			_, err = os.Stdout.Write(value)
			return err
		},
	}
	return cmd
}

func newDeleteCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <entry> <path>",
		Short: "Delete a deposited secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			signer, err := o.signer()
			if err != nil {
				return err
			}
			hc, err := o.httpClient(ctx(cmd))
			if err != nil {
				return err
			}
			bc, err := o.brokerIdentity(ctx(cmd), hc)
			if err != nil {
				return err
			}
			if err := bc.del(ctx(cmd), args[0], args[1], signer); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "deleted %s %s\n", args[0], args[1])
			return nil
		},
	}
	return cmd
}
