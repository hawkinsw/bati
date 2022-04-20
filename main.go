package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hawkinsw/bati/v2/bati"
)

type Type int
type Itab int

func main() {

	var err error

	exitStatus := 0
	defer func() { os.Exit(exitStatus) }()

	/*
	 * Let's define some flags in case we want to use them later!
	 */
	debug := flag.Bool("debug", false, "Enable debugging output")
	decode_type := flag.Bool("type", false, "Decode a _type")
	decode_itab := flag.Bool("itab", false, "Decode an itab")
	var decode_choice interface{}

	inputAddress := flag.String("address", "0x0", "The address of a potential _type/itab to investigate")
	filename := flag.String("filename", "", "The name of the binary to investigate")
	flag.Parse()

	if *decode_type && *decode_itab {
		fmt.Printf("Cannot specify both type and itab for decoding.\n")
		exitStatus = 1
		return
	}

	if *decode_type {
		decode_choice = Type(0)
	} else {
		decode_choice = Itab(0)
	}

	if len(*filename) == 0 {
		fmt.Fprintf(os.Stderr, "Filename to parse is required!\n")
		exitStatus = 1
		return
	}

	binary, err := os.Open(*filename)
	if err != nil {
		fmt.Printf("Could not open '%s' to parse: %v!\n", *filename, err)
		exitStatus = 1
		return
	}
	defer binary.Close()

	inputAddressBase := 10
	if strings.HasPrefix(*inputAddress, "0x") {
		inputAddressBase = 16
		*inputAddress = strings.Replace(*inputAddress, "0x", "", 1)
		if *debug {
			fmt.Printf("Stripped 0x from the beginning of a hex address; I now have %s\n", *inputAddress)
		}
	}

	address, err := strconv.ParseUint(*inputAddress, inputAddressBase, 64)
	if *debug {
		fmt.Printf("Investigating at 0x%x\n", address)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse the given address to investigate (%s): %v\n", *inputAddress, err)
		exitStatus = 1
		return
	}

	b, err := bati.NewBati(binary, *debug)
	if err != nil {
		fmt.Printf("Could not create a Bati: %v\n", err)
		exitStatus = 1
		return
	}

	var decodedType bati.BatiType
	var decodedItab bati.Bati

	switch decode_choice.(type) {
	case Type:
		fmt.Printf("We are decoding a Type\n")
		decodedType, err = b.DecodeTypeAt(address)
	case Itab:
		fmt.Printf("We are decoding an Itab\n")
		decodedItab, err = b.DecodeInterfaceTypeAt(address)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		exitStatus = 1
		return
	}
	switch decode_choice.(type) {
	case Type:
		fmt.Printf("%v\n", decodedType)
	case Itab:
		fmt.Printf("%v\n", decodedItab)
	}
}
