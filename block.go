package blockv

type Block struct {
	pub [57]byte // signer of this block
	sgn [63]byte // signature of md5 digest of previous block's 255 bytes data + this block's 255 bytes data (this block's sgn is all zero in calc)
	dat []byte   // block contents
}
