package blockv

import (
	"crypto/md5"
	"errors"
	"io"
	"net"
	"unsafe"
)

// Block 区块链中的一块。
// 当有分支出现时，将选择
// md5值最小的区块进行链接
// 其余区块将被丢弃，直到
// 在新的链的末尾重新发起
// 链接请求，重复比较过程
type Block struct {
	pub [57]byte // signer of this block
	sln uint8    // signature len
	sgn [64]byte // signature of md5 digest of previous block's 255 bytes data + this block's 255 bytes data (this block's sgn is all zero in calc)
	dat []byte   // block contents
}

func NewBlock(protos ...Protocol) (b *Block, err error) {
	if len(protos) == 0 {
		return
	}
	w := SelectWriter()
	defer w.put()
	for _, p := range protos {
		_, err = io.Copy(w, p)
		if err != nil {
			return
		}
	}
	b = new(Block)
	b.dat = make([]byte, w.Len())
	copy(b.dat, w.Bytes())
	return
}

func (b *Block) Sign(me *Me, prev *Block) error {
	b.pub = me.pubk
	h := md5.New()
	if prev != nil {
		_, err := h.Write((*[57 + 64]byte)(unsafe.Pointer(prev))[:])
		if err != nil {
			return err
		}
		_, err = h.Write(prev.dat)
		if err != nil {
			return err
		}
	}
	_, err := h.Write(b.pub[:])
	if err != nil {
		return err
	}
	_, err = h.Write(make([]byte, 64))
	if err != nil {
		return err
	}
	_, err = h.Write(b.dat)
	if err != nil {
		return err
	}
	digest := h.Sum(nil)
	sgn, err := me.Sign(digest)
	if err != nil {
		return err
	}
	b.sln = uint8(len(sgn))
	copy(b.sgn[:], sgn)
	return nil
}

// Verify pass means digest *[16]byte != nil and err == nil
func (b *Block) Verify(prev *Block) (*[16]byte, error) {
	h := md5.New()
	if prev != nil {
		_, err := h.Write((*[57 + 64]byte)(unsafe.Pointer(prev))[:])
		if err != nil {
			return nil, err
		}
		_, err = h.Write(prev.dat)
		if err != nil {
			return nil, err
		}
	}
	_, err := h.Write(b.pub[:])
	if err != nil {
		return nil, err
	}
	_, err = h.Write(make([]byte, 64))
	if err != nil {
		return nil, err
	}
	_, err = h.Write(b.dat)
	if err != nil {
		return nil, err
	}
	digest := h.Sum(nil)
	if Verify(b.pub[:], digest, b.sgn[:b.sln]) {
		return (*[16]byte)((*slice)(unsafe.Pointer(&digest)).data), nil
	}
	return nil, errors.New("verification failed")
}

// Buffer is used to marshal block into bytes
func (b *Block) Buffer() (buf net.Buffers) {
	buf = make(net.Buffers, 2)
	buf[0] = *(*[]byte)(unsafe.Pointer(&slice{
		data: unsafe.Pointer(b),
		len:  57 + 1 + 64,
		cap:  57 + 1 + 64,
	}))
	buf[1] = b.dat
	return
}
