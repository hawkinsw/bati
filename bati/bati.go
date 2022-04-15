package bati

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hawkinsw/bati/v2/bati/runtime"
	"github.com/saferwall/elf"
)

type BatiDecoder struct {
	sourceElf *elf.Parser
	debug     bool
}

type BatiType struct {
	Size           uint64
	PtrData        uint64
	Hash           uint32
	Tflag          uint8
	Align          uint8
	FieldAlign     uint8
	Kind           uint8
	ComparisonFunc uint64
	GcData         uint64
	Name           string
	PtrToThisType  uint32
}

type BatiFace struct {
	tipe    BatiType
	pkgpath string
	// methods!!
}

type Bati struct {
	base       uint64
	moduleBase uint64
	iface      *BatiFace
	tipe       *BatiType
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

	rodataAddress, err := b.findSectionAddress(".rodata")
	if err != nil {
		return Bati{base, 0, nil, nil}, err
	}
	constructedBati := Bati{base, rodataAddress, &BatiFace{}, &BatiType{}}
	moduleOffset := runtime.NewBaseOffset(rodataAddress)

	sizeof_type := uint64(48)
	//sizeof_name := uint64(8)

	containingSection, err := b.findSectionForAddress(base)
	if err != nil {
		return Bati{base, 0, nil, nil}, err
	}
	containingSectionData, _ := containingSection.Data()
	containingOffset := base - containingSection.Addr

	addressOfInterface := binary.LittleEndian.Uint32(containingSectionData[containingOffset:(containingOffset + 4)])
	if b.debug {
		fmt.Printf("Address of the Interface: %x\n", addressOfInterface)
	}

	// Find (and configure) everything that we need to look at the itab's interface.
	containingSection, err = b.findSectionForAddress(uint64(addressOfInterface))
	if err != nil {
		return Bati{base, 0, nil, nil}, err
	}
	containingSectionData, _ = containingSection.Data()
	containingOffset = uint64(addressOfInterface) - containingSection.Addr

	interfaceTypeTypeOffset := containingOffset
	interfaceTypePkgPathOffset := interfaceTypeTypeOffset + sizeof_type

	//interfaceIMethodOffset := interfaceTypeTypeOffset + sizeof_type + sizeof_name

	interfaceOffsetIterator := uint64(0)
	// These are the fields of the _type as they exist in the binary (48 total bytes).
	// 1: size (8 bytes)
	constructedBati.iface.tipe.Size = binary.LittleEndian.Uint64(containingSectionData[interfaceTypeTypeOffset:(interfaceTypeTypeOffset + 8)])
	interfaceOffsetIterator += 8
	// 2: ptrdata (8 bytes)
	constructedBati.iface.tipe.PtrData = binary.LittleEndian.Uint64(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 8)])
	interfaceOffsetIterator += 8
	// 3: hash (4 bytes)
	constructedBati.iface.tipe.Hash = uint32(binary.LittleEndian.Uint32(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 4)]))
	interfaceOffsetIterator += 4

	// 4: tflag (1 byte)
	constructedBati.iface.tipe.Tflag = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 5: align (1 byte)
	constructedBati.iface.tipe.Align = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 6: fieldAlign (1 byte)
	constructedBati.iface.tipe.FieldAlign = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 7: kind (1 byte)
	constructedBati.iface.tipe.Kind = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 8: comparison function (8 bytes)
	constructedBati.iface.tipe.ComparisonFunc = binary.LittleEndian.Uint64(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 8)])
	interfaceOffsetIterator += 8

	// 9: gcdata (8 bytes)
	constructedBati.iface.tipe.GcData = binary.LittleEndian.Uint64(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 8)])
	interfaceOffsetIterator += 8

	// 10: name (4 bytes)
	interfaceTypeName := binary.LittleEndian.Uint32(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 4)])
	interfaceOffsetIterator += 4

	// Convert from a "name offset" to an actual string
	interfaceNameAddress := moduleOffset.NameOff(interfaceTypeName)
	sectionForInterfaceTypeName, _ := b.findSectionForAddress(uint64(interfaceNameAddress))
	sectionForInterfaceTypeNameData, _ := sectionForInterfaceTypeName.Data()
	interfaceTypeNameSectionOffset := interfaceNameAddress - sectionForInterfaceTypeName.Addr
	interfaceTypeNameName := runtime.NewName(&sectionForInterfaceTypeNameData[interfaceTypeNameSectionOffset])
	constructedBati.iface.tipe.Name = interfaceTypeNameName.ToString()

	if b.debug {
		fmt.Printf("Interface name: %v\n", constructedBati.iface.tipe.Name)
	}

	// 11: ptrToThis (4 bytes)
	constructedBati.iface.tipe.PtrToThisType = binary.LittleEndian.Uint32(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 4)])
	interfaceOffsetIterator += 4

	if interfaceOffsetIterator != sizeof_type {
		fmt.Printf("Error: Could not parse the interface's _type field.\n")
	}

	// Next, there is a 8-byte pointer to a _runtime_ string that holds the package's path!
	pkgNamePointer := binary.LittleEndian.Uint64(containingSectionData[interfaceTypePkgPathOffset:(interfaceTypePkgPathOffset + 8)])
	sectionForPkgNamePointer, _ := b.findSectionForAddress(uint64(pkgNamePointer))
	sectionForPkgNamePointerData, _ := sectionForPkgNamePointer.Data()
	pkgNameDataOffset := uint64(pkgNamePointer) - sectionForPkgNamePointer.Addr
	pkgNameName := runtime.NewName(&sectionForPkgNamePointerData[pkgNameDataOffset])
	pkgNameString := pkgNameName.ToString()

	if b.debug {
		fmt.Printf("Address of the package name for the interface: %x\n", pkgNamePointer)
		fmt.Printf("pkgname: %v\n", pkgNameString)
	}

	// TODO: Make sure that we handle the pointers to the methods!

	return constructedBati, nil
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

func (b *BatiDecoder) nameForSection(section *elf.ELF64Section) (string, error) {
	shstrtab, err := b.sourceElf.F.Sections64[b.sourceElf.F.Header64.Shstrndx].Data()
	if err != nil {
		return "", err
	}
	if name, successful := stringInBytes(shstrtab, int(section.Name)); successful {
		return name, nil
	}
	return "", fmt.Errorf("No name for section.")
}

func (b *BatiDecoder) findSectionForAddress(base uint64) (*elf.ELF64Section, error) {
	for _, ss := range b.sourceElf.F.Sections64 {
		if ss.Addr <= base && base < ss.Addr+ss.Size {
			if b.debug {
				name := "??"
				if sectionName, err := b.nameForSection(ss); err == nil {
					name = sectionName
				}
				fmt.Printf("Found 0x%x in %s section\n", base, name)
			}
			return ss, nil
		}
	}
	return nil, fmt.Errorf("No section for address 0x%x\n", base)
}

func (b *BatiDecoder) findSectionAddress(name string) (uint64, error) {
	for _, ss := range b.sourceElf.F.Sections64 {
		if sectionName, err := b.nameForSection(ss); err == nil {
			if sectionName == name {
				return ss.Addr, nil
			}
		}
	}
	return 0, fmt.Errorf("Could not find section named %s\n", name)
}
