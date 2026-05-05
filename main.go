package main

import (
	"os"

	"secrethunter/cmd"
)

func main() {
	os.Exit(run())
}

func run() int {
	cmd.RunCLI()
	return 0
}