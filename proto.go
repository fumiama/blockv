package blockv

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

// ProtoType is used to decide whether Protocol should be called
// when parsing Block.dat
type ProtoType uint8

// Protocol wrap any data format into Block.dat
type Protocol interface {
	// take a wrapped data into self and consume it
	io.Writer
	// write data into buffer
	io.Reader
	// length of data that will be write by calling Read
	Len() int
	// protocol name
	fmt.Stringer
	// protocol type
	Type() ProtoType
	// new self instance
	New() Protocol
}

var (
	prototypes = map[ProtoType]Protocol{}
	protosmu   sync.RWMutex
)

func RegisterProtocol(p Protocol) error {
	protosmu.Lock()
	defer protosmu.Unlock()
	typ := p.Type()
	pp, ok := prototypes[typ]
	if ok {
		return errors.New("type " + strconv.Itoa(int(typ)) + " has been occupied by " + pp.String())
	}
	prototypes[typ] = p
	return nil
}
