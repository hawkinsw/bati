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
	typeTable map[uint64]*BatiType
	debug     bool
}

const SIZEOF_TYPE uint64 = uint64(48)

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
	PtrToThisType  *BatiType
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

	return &BatiDecoder{parser, make(map[uint64]*BatiType), debug}, nil
}

func (b BatiType) String() string {
	return "Bati Stringify!"
}
func (b BatiFace) String() string {
	return "BatiFace Stringify!"
}
func (b Bati) String() string {
	return "Bati Stringify!"
}

func (b *BatiDecoder) DecodeTypeAt(base uint64) (BatiType, error) {

	/*
	 * First, check the type table! We may have already done this one!
	 */
	if b.typeTable[base] != nil {
		if b.debug {
			fmt.Printf("Got type at 0x%x from the cache!\n", base)
		}
		return *b.typeTable[base], nil
	} else if b.debug {
		fmt.Printf("Could not find 0x%x in cache -- decoding!\n", base)
	}
	constructedBatiType := BatiType{}

	rodataAddress, err := b.findSectionAddress(".rodata")
	if err != nil {
		return constructedBatiType, err
	}
	moduleOffset := runtime.NewBaseOffset(rodataAddress)

	containingSection, err := b.findSectionForAddress(base)
	if err != nil {
		return constructedBatiType, err
	}
	containingSectionData, _ := containingSection.Data()
	containingOffset := uint64(base) - containingSection.Addr

	interfaceTypeTypeOffset := containingOffset

	//interfaceIMethodOffset := interfaceTypeTypeOffset + sizeof_type + sizeof_name

	interfaceOffsetIterator := uint64(0)
	// These are the fields of the _type as they exist in the binary (48 total bytes).
	// 1: size (8 bytes)
	constructedBatiType.Size = binary.LittleEndian.Uint64(containingSectionData[interfaceTypeTypeOffset:(interfaceTypeTypeOffset + 8)])
	interfaceOffsetIterator += 8
	// 2: ptrdata (8 bytes)
	constructedBatiType.PtrData = binary.LittleEndian.Uint64(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 8)])
	interfaceOffsetIterator += 8
	// 3: hash (4 bytes)
	constructedBatiType.Hash = uint32(binary.LittleEndian.Uint32(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 4)]))
	interfaceOffsetIterator += 4

	// 4: tflag (1 byte)
	constructedBatiType.Tflag = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 5: align (1 byte)
	constructedBatiType.Align = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 6: fieldAlign (1 byte)
	constructedBatiType.FieldAlign = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 7: kind (1 byte)
	constructedBatiType.Kind = byte(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator)])
	interfaceOffsetIterator += 1

	// 8: comparison function (8 bytes)
	constructedBatiType.ComparisonFunc = binary.LittleEndian.Uint64(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 8)])
	interfaceOffsetIterator += 8

	// 9: gcdata (8 bytes)
	constructedBatiType.GcData = binary.LittleEndian.Uint64(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 8)])
	interfaceOffsetIterator += 8

	// 10: name (4 bytes)
	interfaceTypeName := binary.LittleEndian.Uint32(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 4)])
	interfaceOffsetIterator += 4

	// Convert from a "name offset" to an actual string
	interfaceNameAddress := moduleOffset.NameOff(interfaceTypeName)
	sectionForInterfaceTypeName, err := b.findSectionForAddress(uint64(interfaceNameAddress))
	if err == nil {
		sectionForInterfaceTypeNameData, _ := sectionForInterfaceTypeName.Data()
		interfaceTypeNameSectionOffset := interfaceNameAddress - sectionForInterfaceTypeName.Addr
		interfaceTypeNameName := runtime.NewName(&sectionForInterfaceTypeNameData[interfaceTypeNameSectionOffset])
		constructedBatiType.Name = interfaceTypeNameName.ToString()

		if b.debug {
			fmt.Printf("Interface name: %v\n", constructedBatiType.Name)
		}
	}

	// 11: ptrToThis (4 bytes)
	PtrToThisTypeOffset := binary.LittleEndian.Uint32(containingSectionData[(interfaceTypeTypeOffset + interfaceOffsetIterator):(interfaceTypeTypeOffset + interfaceOffsetIterator + 4)])
	interfaceOffsetIterator += 4

	if PtrToThisTypeOffset != 0 {
		ptrToThisAddress := moduleOffset.TypeOff(PtrToThisTypeOffset)
		PtrToThisType, err := b.DecodeTypeAt(ptrToThisAddress)

		if err != nil {
			fmt.Printf("Warning: Could not decode a type at the type's pointer-to-this offset. Tried at 0x%x.\n", ptrToThisAddress)
		} else {
			constructedBatiType.PtrToThisType = &PtrToThisType
			if b.debug {
				fmt.Printf("Ptr to this type's name: %s\n", PtrToThisType.Name)
			}
		}
	} else if b.debug {
		fmt.Printf("Skipping the decode of a ptr-to-this field because it is nil.\n")
	}

	if interfaceOffsetIterator != SIZEOF_TYPE {
		return BatiType{}, fmt.Errorf("Could not parse the _type field at 0x%x\n", base)
	}

	b.typeTable[base] = &constructedBatiType
	return constructedBatiType, nil
}

func (b *BatiDecoder) DecodeInterfaceTypeAt(base uint64) (Bati, error) {

	rodataAddress, err := b.findSectionAddress(".rodata")
	if err != nil {
		return Bati{base, 0, nil, nil}, err
	}
	constructedBati := Bati{base, rodataAddress, &BatiFace{}, &BatiType{}}

	containingSection, err := b.findSectionForAddress(base)
	if err != nil {
		return Bati{base, 0, nil, nil}, err
	}
	containingSectionData, _ := containingSection.Data()
	containingOffset := base - containingSection.Addr

	addressOfInterface := binary.LittleEndian.Uint64(containingSectionData[containingOffset:(containingOffset + 8)])
	if b.debug {
		fmt.Printf("Address of the Interface: %x\n", addressOfInterface)
	}

	constructedBati.iface.tipe, err = b.DecodeTypeAt(uint64(addressOfInterface))
	if err != nil {
		return constructedBati, err
	}

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
