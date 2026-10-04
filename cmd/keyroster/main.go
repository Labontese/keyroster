// Command keyroster is the admin and user CLI of keyroster, a self-hosted SSH
// certificate authority and access roster.
package main

import (
	"context"
	"os"
)

func main() {
	os.Exit(dispatch(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
