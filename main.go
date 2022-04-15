package main

import (
	"fmt"
	"os"

	"github.com/hawkinsw/bati/v2/bati"
)

func main() {
	fmt.Printf("Hello, World\n")
	binary, err := os.Open("./binary")

	if err != nil {
		fmt.Printf("Could not open binary to parse: %v!\n", err)
		return
	}

	defer binary.Close()

	b, err := bati.NewBati(binary, true)

	if err != nil {
		fmt.Printf("Could not create a Bati: %v\n", err)
	}

	_, _ = b.DecodeAt(0x4b45d8)

}
