package main

import (
	"fmt"
	"os"

	"github.com/hawkinsw/bati/v2/bati"
)

func main() {
	binary, err := os.Open("./play")

	if err != nil {
		fmt.Printf("Could not open binary to parse: %v!\n", err)
		return
	}

	defer binary.Close()

	b, err := bati.NewBati(binary, true)

	if err != nil {
		fmt.Printf("Could not create a Bati: %v\n", err)
	}

	_, _ = b.DecodeAt(0x4b5da0)
}
