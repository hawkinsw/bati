package bati

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/saferwall/elf"
)

type BatiDecoder struct {
	sourceElf *elf.Parser
	debug     bool
}

type BatiType struct {
}

type BatiFace struct {
	tipe    BatiType
	pkgpath string
	// methods!!
}

type Bati struct {
	base  uint64
	iface *BatiFace
	tipe  *BatiType
}

func NewBati(source io.Reader, debug bool) (*BatiDecoder, error) {

	sourceBytes, err := io.ReadAll(source)

	if err != nil {
		return nil, err
	}
	parser, err := elf.NewBytes(sourceBytes)

	if err != nil {
		return nil, err
	}

	if err = parser.ParseELFHeader(elf.ELFCLASS64); err != nil {
		return nil, err
	}
	if err = parser.ParseELFSectionHeaders(elf.ELFCLASS64); err != nil {
		return nil, err
	}
	if err = parser.ParseELFSections(elf.ELFCLASS64); err != nil {
		return nil, err
	}

	return &BatiDecoder{parser, debug}, nil
}

func (b *BatiDecoder) DecodeAt(base uint64) (Bati, error) {
	sectionForBase, err := b.findSectionForAddress(base)
	if err != nil {
		return Bati{base, nil, nil}, err
	}
	sectionForBaseData, _ := sectionForBase.Data()
	baseOffsetInSection := base - sectionForBase.Addr

	addressOfInterface := binary.LittleEndian.Uint32(sectionForBaseData[baseOffsetInSection:(baseOffsetInSection + 4)])

	if b.debug {
		fmt.Printf("Address of the Interface: %x\n", addressOfInterface)
	}
	return Bati{base, nil, nil}, nil
}

/*
 * Utilities
 */
func stringInBytes(bites []byte, start int) (string, bool) {
	if start >= len(bites) {
		return "", false
	}
	for end := start; end < len(bites); end++ {
		if bites[end] == 0 {
			return string(bites[start:end]), true
		}
	}
	return "", false
}

func nameForSection(section *elf.ELF64Section, p *elf.Parser) (string, error) {
	shstrtab, err := p.F.Sections64[p.F.Header64.Shstrndx].Data()
	if err != nil {
		return "", err
	}
	if name, successful := stringInBytes(shstrtab, int(section.Name)); successful {
		return name, nil
	}
	return "", fmt.Errorf("Coult not find the name for the section.")
}

func (b *BatiDecoder) findSectionForAddress(base uint64) (*elf.ELF64Section, error) {
	for _, ss := range b.sourceElf.F.Sections64 {
		if ss.Addr <= base && base < ss.Addr+ss.Size {
			if b.debug {
				name := "No name found"

				if sectionName, err := nameForSection(ss, b.sourceElf); err == nil {
					name = sectionName
				}
				fmt.Printf("Found itab in %s section\n", name)
			}
			return ss, nil
		}
	}
	return nil, fmt.Errorf("Could not find the section for address %d\n", base)
}
