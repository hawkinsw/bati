package bati

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hawkinsw/bati/v2/bati/runtime"
	"github.com/saferwall/elf"
)

func readByte(
	data []byte,
	offset uint64,
) (value byte, nextOffset uint64, err error) {
	value = byte(data[offset])
	byte_len := uint64(1)
	nextOffset = offset + byte_len
	err = nil
	return
}

func readLe64(
	data []byte,
	offset uint64,
) (value uint64, nextOffset uint64, err error) {
	uint64_len := uint64(8)
	value = binary.LittleEndian.Uint64(
		data[offset:(offset + uint64_len)],
	)
	err = nil
	nextOffset = offset + uint64_len
	return
}

func readLe32(
	data []byte,
	offset uint64,
) (value uint32, nextOffset uint64, err error) {
	uint32_len := uint64(8)
	value = binary.LittleEndian.Uint32(
		data[offset:(offset + uint32_len)],
	)
	err = nil
	nextOffset = offset + uint32_len
	return
}

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

type BatiIMethod struct {
	Name string
	Type BatiType
}

type BatiMethod struct {
	Name    string
	Address uint64
}

type BatiFace struct {
	tipe     BatiType
	pkgpath  string
	imethods []BatiIMethod
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

func (b BatiIMethod) String() string {
	result := fmt.Sprintf("Method: %v\n", b.Name)
	result += fmt.Sprintf("Type: %v", b.Type)
	return result
}

func (b BatiType) String() string {
	result := fmt.Sprintf("Name: %v\n", b.Name)
	result += fmt.Sprintf("&this: %v\n", func() string {
		if b.PtrToThisType != nil {
			return b.PtrToThisType.Name
		} else {
			return "none"
		}
	}())
	return result
}

func (b BatiFace) String() string {
	result := fmt.Sprintf("Type:\n%v\n", b.tipe)
	result += fmt.Sprintf("Interface package path: %v\n", b.pkgpath)
	result += fmt.Sprintf("Interface methods\n")
	for _, method := range b.imethods {
		result += fmt.Sprintf("%v\n", method)
	}
	return result
}

func (b Bati) String() string {
	result := fmt.Sprintf("Interface:\n")
	result += fmt.Sprintf("%v\n", b.iface)
	result += fmt.Sprintf("\nType:\n")
	result += fmt.Sprintf("%v\n", b.tipe)
	return result
}

func (b *BatiDecoder) DecodeImethodSliceAt(base uint64) ([]BatiIMethod, error) {

	rodataAddress, err := b.findSectionAddress(".rodata")
	if err != nil {
		return nil, err
	}
	moduleOffset := runtime.NewBaseOffset(rodataAddress)
	methods := make([]BatiIMethod, 0)

	// This is a slice!
	// In other words, it should be a pointer to the backing data (an array),
	// then two uint64_t (the capacity and the size).

	sectionContainingBase, err := b.findSectionForAddress(base)
	if err != nil {
		return nil, err
	}
	sectionContaingBaseData, _ := sectionContainingBase.Data()
	sectionContainingBaseNextReadOffset := uint64(
		base,
	) - sectionContainingBase.Addr

	addressOfImethodSliceBacking, sectionContainingBaseNextReadOffset, err := readLe64(
		sectionContaingBaseData,
		sectionContainingBaseNextReadOffset,
	)
	if err != nil {
		if b.debug {
			fmt.Printf(
				"Error reading the address of the data backing the imethod slice: %v\n",
				err,
			)
		}
		return nil, err
	}

	if addressOfImethodSliceBacking == 0 {
		if b.debug {
			fmt.Printf("No methods found!\n")
		}
		return methods, nil
	}

	sizeOfImethodsSlice, sectionContainingBaseNextReadOffset, err := readLe64(
		sectionContaingBaseData,
		sectionContainingBaseNextReadOffset,
	)
	capacityOfImethodsSlice, sectionContainingBaseNextReadOffset, err := readLe64(
		sectionContaingBaseData,
		sectionContainingBaseNextReadOffset,
	)

	if b.debug {
		fmt.Printf("Methods are at 0x%x!\n", addressOfImethodSliceBacking)
		fmt.Printf("imethods slice has %v size!\n", sizeOfImethodsSlice)
		fmt.Printf("imethods slice has %v capacity!\n", capacityOfImethodsSlice)
	}

	sectionContainingImethodSliceBacking, err := b.findSectionForAddress(
		addressOfImethodSliceBacking,
	)
	sectionContainingImethodSliceBackingData, err := sectionContainingImethodSliceBacking.Data()
	for i := uint64(0); i < sizeOfImethodsSlice; i++ {
		nameOffAddress := uint64(i*8) + addressOfImethodSliceBacking
		containingOffset := nameOffAddress - sectionContainingImethodSliceBacking.Addr
		nameOff, containingOffset, err := readLe32(sectionContainingImethodSliceBackingData, containingOffset)
		if err != nil {
			if b.debug {
				fmt.Printf("Could not get the address of the name of the method: %v\n", err)
			}
			return nil, err
		}
		methodName, err := b.stringFromStringOffset(rodataAddress, nameOff)
		if err != nil {
			if b.debug {
				fmt.Printf("Could not get the name of the method: %v\n", err)
			}
			return nil, err
		}
		if b.debug {
			fmt.Printf("method name: %v\n", methodName)
		}
		typeOff, containingOffset, err := readLe32(sectionContainingImethodSliceBackingData, containingOffset)
		if err != nil {
			if b.debug {
				fmt.Printf("Could not get the address of the type of the method: %v\n", err)
			}
			return nil, err
		}
		methodType, err := b.DecodeTypeAt(moduleOffset.TypeOff(typeOff))
		if err != nil {
			if b.debug {
				fmt.Printf("Could not get the type of the name of the method: %v\n", err)
			}
			return nil, err
		}
		if b.debug {
			fmt.Printf("method type: %v\n", methodType)
		}

		methods = append(methods, BatiIMethod{methodName, methodType})
	}
	return methods, nil
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

	// These are the fields of the _type as they exist in the binary (48 total
	// bytes).
	// 1: size (8 bytes)
	constructedBatiType.Size, interfaceTypeTypeOffset, _ = readLe64(containingSectionData, interfaceTypeTypeOffset)
	// 2: ptrdata (8 bytes)
	constructedBatiType.PtrData, interfaceTypeTypeOffset, _ = readLe64(containingSectionData, interfaceTypeTypeOffset)
	// 3: hash (4 bytes)
	constructedBatiType.Hash, interfaceTypeTypeOffset, _ = readLe32(containingSectionData, interfaceTypeTypeOffset)
	// 4: tflag (1 byte)
	constructedBatiType.Tflag, interfaceTypeTypeOffset, _ = readByte(containingSectionData, interfaceTypeTypeOffset)
	// 5: align (1 byte)
	constructedBatiType.Align, interfaceTypeTypeOffset, _ = readByte(containingSectionData, interfaceTypeTypeOffset)
	// 6: fieldAlign (1 byte)
	constructedBatiType.FieldAlign, interfaceTypeTypeOffset, _ = readByte(containingSectionData, interfaceTypeTypeOffset)
	// 7: kind (1 byte)
	constructedBatiType.Kind, interfaceTypeTypeOffset, _ = readByte(containingSectionData, interfaceTypeTypeOffset)

	// 8: comparison function (8 bytes)
	constructedBatiType.ComparisonFunc, interfaceTypeTypeOffset, _ = readLe64(containingSectionData, interfaceTypeTypeOffset)

	// 9: gcdata (8 bytes)
	constructedBatiType.GcData, interfaceTypeTypeOffset, _ = readLe64(containingSectionData, interfaceTypeTypeOffset)

	// 10: name (4 bytes)
	typeName, interfaceTypeTypeOffset, _ := readLe32(containingSectionData, interfaceTypeTypeOffset)

	// Convert from a "name offset" to an actual string
	constructedBatiType.Name, err = b.stringFromStringOffset(
		rodataAddress,
		typeName,
	)
	if err == nil {
		if b.debug {
			fmt.Printf("Type name: %v\n", constructedBatiType.Name)
		}
	}

	// 11: ptrToThis (4 bytes)
	PtrToThisTypeOffset, interfaceTypeTypeOffset, _ := readLe32(containingSectionData, interfaceTypeTypeOffset)

	if PtrToThisTypeOffset != 0 {
		ptrToThisAddress := moduleOffset.TypeOff(PtrToThisTypeOffset)
		PtrToThisType, err := b.DecodeTypeAt(ptrToThisAddress)

		if err != nil {
			fmt.Printf(
				"Warning: Could not decode a type at the type's pointer-to-this offset. Tried at 0x%x.\n",
				ptrToThisAddress,
			)
		} else {
			constructedBatiType.PtrToThisType = &PtrToThisType
			if b.debug {
				fmt.Printf("Ptr to this type's name: %s\n", PtrToThisType.Name)
			}
		}
	} else if b.debug {
		fmt.Printf("Skipping the decode of a ptr-to-this field because it is nil.\n")
	}

	b.typeTable[base] = &constructedBatiType
	return constructedBatiType, nil
}

func (b *BatiDecoder) stringFromStringOffset(
	base uint64,
	offset uint32,
) (string, error) {
	// Convert from an "offset" to an actual string
	moduleOffset := runtime.NewBaseOffset(base)
	stringAddress := moduleOffset.StringOff(offset)
	return b.stringFromStringAddress(stringAddress)
}

func (b *BatiDecoder) stringFromStringAddress(
	string_address uint64,
) (string, error) {
	sectionForStringAddress, err := b.findSectionForAddress(
		uint64(string_address),
	)
	if err == nil {
		sectionForStringData, _ := sectionForStringAddress.Data()
		sectionForStringDataOffset := string_address - sectionForStringAddress.Addr
		stringString := runtime.NewString(
			&sectionForStringData[sectionForStringDataOffset],
		)

		if b.debug {
			fmt.Printf(
				"stringFromStringAddress result: %v\n",
				stringString.ToString(),
			)
		}
		return stringString.ToString(), nil
	}

	return "", err
}

func (b *BatiDecoder) DecodeItabAt(base uint64) (Bati, error) {
	constructedBati := Bati{base, 0, nil, nil}
	errorBati := Bati{base, 0, nil, nil}

	containingSection, err := b.findSectionForAddress(base)
	if err != nil {
		return errorBati, err
	}
	containingSectionData, _ := containingSection.Data()
	containingOffset := base - containingSection.Addr

	addressOfInterface, containingOffset, err := readLe64(containingSectionData, containingOffset)
	addressOfType, containingOffset, err := readLe64(containingSectionData, containingOffset)

	if b.debug {
		fmt.Printf("Address of the Interface: %x\n", addressOfInterface)
		fmt.Printf("Address of the Type: %x\n", addressOfType)
	}

	iface, err := b.DecodeInterfaceTypeAt(addressOfInterface)

	if err != nil {
		fmt.Printf("Could not parse an interface type at the base of a Itab\n")
		return errorBati, err
	}
	constructedBati.iface = &iface

	tipe, err := b.DecodeTypeAt(addressOfType)
	if err != nil {
		fmt.Printf("Could not parse a type at the base of a Itab\n")
		return errorBati, err
	}
	constructedBati.tipe = &tipe

	return constructedBati, nil

}

func (b *BatiDecoder) DecodeInterfaceTypeAt(base uint64) (BatiFace, error) {
	constructedBatiFace := BatiFace{}
	errorBatiFace := BatiFace{}

	sectionContainingInterface, err := b.findSectionForAddress(base)
	sectionContainingInterfaceData, err := sectionContainingInterface.Data()
	sectionContainingInterfaceOffset := base - sectionContainingInterface.Addr

	pkgPathNameName := base + SIZEOF_TYPE
	iMethodSlice := base + SIZEOF_TYPE + 8

	constructedBatiFace.tipe, err = b.DecodeTypeAt(uint64(base))
	if err != nil {
		return errorBatiFace, err
	}

	sectionContainingInterfaceOffset = pkgPathNameName - sectionContainingInterface.Addr
	pkgPathNameAddress, sectionContainingInterfaceOffset, _ := readLe64(sectionContainingInterfaceData, sectionContainingInterfaceOffset)
	pkgName, err := b.stringFromStringAddress(pkgPathNameAddress)
	if err != nil {
		if b.debug {
			fmt.Printf("Could not read the package path for an interface: %v\n", err)
		}
		return errorBatiFace, err
	}
	constructedBatiFace.pkgpath = pkgName

	constructedBatiFace.imethods, err = b.DecodeImethodSliceAt(iMethodSlice)
	if err != nil {
		if b.debug {
			fmt.Printf("Could not decode the methods for an interface: %v\n", err)
		}
		return errorBatiFace, err
	}

	return constructedBatiFace, nil
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

func (b *BatiDecoder) nameForSection(
	section *elf.ELF64Section,
) (string, error) {
	shstrtab, err := b.sourceElf.F.Sections64[b.sourceElf.F.Header64.Shstrndx].Data()
	if err != nil {
		return "", err
	}
	if name, successful := stringInBytes(shstrtab, int(section.Name)); successful {
		return name, nil
	}
	return "", fmt.Errorf("No name for section.")
}

func (b *BatiDecoder) findSectionForAddress(
	base uint64,
) (*elf.ELF64Section, error) {
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
