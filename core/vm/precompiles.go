package vm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/tenderly/rsk-core/crypto"
)

var (
	errBlockHeaderInvalidInput      = errors.New("invalid input length")
	errBlockHeaderInvalidSignature  = errors.New("invalid input data")
	errBlockHeaderInvalidBlockDepth = errors.New("invalid block depth")
	errBlockHeaderInvalidBlockHash  = errors.New("invalid block hash")

	bytesType, _    = abi.NewType("bytes", "", nil)
	intType, _      = abi.NewType("int256", "", nil)
	stringType, _   = abi.NewType("string", "", nil)
	bytesArrType, _ = abi.NewType("bytes[]", "", nil)

	bytesArg    = abi.Argument{Name: "", Type: bytesType, Indexed: false}
	intArg      = abi.Argument{Name: "", Type: intType, Indexed: false}
	stringArg   = abi.Argument{Name: "", Type: stringType, Indexed: false}
	bytesArrArg = abi.Argument{Name: "", Type: bytesArrType, Indexed: false}
)

type blockHeader struct {
	getHash   func(uint64) common.Hash
	getHeader func(common.Hash, uint64) *types.Header

	blockNumber uint64

	functions map[[4]byte]BlockHeaderContract
}

func newBlockHeader(blockContext BlockContext) blockHeader {
	getBlockHashMethod := abi.NewMethod("getBlockHash", "getBlockHash", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getBitcoinHeaderMethod := abi.NewMethod("getBitcoinHeader", "getBitcoinHeader", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getCoinbaseAddressMethod := abi.NewMethod("getCoinbaseAddress", "getCoinbaseAddress", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getDifficultyMethod := abi.NewMethod("getDifficulty", "getDifficulty", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getGasLimitMethod := abi.NewMethod("getGasLimit", "getGasLimit", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getGasUsedMethod := abi.NewMethod("getGasUsed", "getGasUsed", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getMergedMiningTagsMethod := abi.NewMethod("getMergedMiningTags", "getMergedMiningTags", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{stringArg})
	getMinGasPriceMethod := abi.NewMethod("getMinGasPrice", "getMinGasPrice", abi.Function, "", false, false, abi.Arguments{intArg}, abi.Arguments{bytesArg})
	getUncleCoinbaseAddressMethod := abi.NewMethod("getUncleCoinbaseAddress", "getUncleCoinbaseAddress", abi.Function, "", false, false, abi.Arguments{intArg, intArg}, abi.Arguments{bytesArg})

	return blockHeader{
		getHash:     blockContext.GetHash,
		getHeader:   blockContext.GetHeader,
		blockNumber: blockContext.BlockNumber.Uint64(),
		functions: map[[4]byte]BlockHeaderContract{
			signatureFromID(getBlockHashMethod.ID):            blockHash{getBlockHashMethod},
			signatureFromID(getBitcoinHeaderMethod.ID):        bitcoinHeader{getBitcoinHeaderMethod},
			signatureFromID(getCoinbaseAddressMethod.ID):      coinbaseAddress{getCoinbaseAddressMethod},
			signatureFromID(getDifficultyMethod.ID):           difficulty{getDifficultyMethod},
			signatureFromID(getGasLimitMethod.ID):             gasLimit{getGasLimitMethod},
			signatureFromID(getGasUsedMethod.ID):              gasUsed{getGasUsedMethod},
			signatureFromID(getMergedMiningTagsMethod.ID):     mergedMiningTags{getMergedMiningTagsMethod},
			signatureFromID(getMinGasPriceMethod.ID):          minGasPrice{getMinGasPriceMethod},
			signatureFromID(getUncleCoinbaseAddressMethod.ID): uncleCoinbaseAddress{getUncleCoinbaseAddressMethod},
		},
	}
}

type BlockHeaderContract interface {
	run(header *types.Header, arguments ...[]byte) ([]byte, error)
}

func (bh blockHeader) RequiredGas(input []byte) uint64 {
	return 4000 + uint64(len(input))*2
}

func (bh blockHeader) Run(input []byte) ([]byte, error) {
	if len(input) != 36 && len(input) != 68 {
		return nil, errBlockHeaderInvalidInput
	}

	function, ok := bh.getFunction(input)
	if !ok {
		return nil, errBlockHeaderInvalidSignature
	}

	blockDepth := new(big.Int).SetBytes(input[4:36])
	if !blockDepth.IsInt64() {
		return nil, errBlockHeaderInvalidBlockDepth
	}

	number := blockDepth.Uint64()
	hash := bh.getHash(number)

	header := bh.getHeader(hash, number)
	if header == nil {
		return nil, errBlockHeaderInvalidBlockHash
	}

	return function.run(header, input[36:])
}

type blockHash struct {
	method abi.Method
}

func (bh blockHash) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	return bh.method.Outputs.Pack(header.Hash().Bytes())
}

type bitcoinHeader struct {
	method abi.Method
}

// we really don't want to change header structure
// therefore we'll encode bitcoinHeader to extraData parameter
func (bh bitcoinHeader) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	size := getMergedMiningTagsTotalSize(header.Extra)

	extra := header.Extra[len(header.Extra)-size-81 : len(header.Extra)-size-1]
	return bh.method.Outputs.Pack(extra)
}

type coinbaseAddress struct {
	method abi.Method
}

func (ca coinbaseAddress) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	return ca.method.Outputs.Pack(header.Coinbase.Bytes())
}

type difficulty struct {
	method abi.Method
}

func (d difficulty) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	return d.method.Outputs.Pack(header.Difficulty.Bytes())
}

type gasLimit struct {
	method abi.Method
}

func (gl gasLimit) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b, header.GasLimit)
	return gl.method.Outputs.Pack(b)
}

type gasUsed struct {
	method abi.Method
}

func (gu gasUsed) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b, header.GasUsed)
	return gu.method.Outputs.Pack(b)
}

type mergedMiningTags struct {
	method abi.Method
}

// we really don't want to change header structure
// therefore we'll encode mergedMiningTags to extraData parameter
func (mmt mergedMiningTags) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	mergedMiningTagsSize := getMergedMiningTagsSize(header.Extra)
	size := getMinGasPriceSizeTotal(header.Extra)

	mergedMiningTags := header.Extra[len(header.Extra)-mergedMiningTagsSize-size-1 : len(header.Extra)-size-1]
	return mmt.method.Outputs.Pack(mergedMiningTags)
}

type minGasPrice struct {
	method abi.Method
}

// we really don't want to change header structure
// therefore we'll encode minGasPrice to extraData parameter
func (mgp minGasPrice) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	size := getUncleCoinbaseAddressSizeTotal(header.Extra)
	minGasPrice := header.Extra[len(header.Extra)-size-33 : len(header.Extra)-size-1]

	return mgp.method.Outputs.Pack(minGasPrice)
}

type uncleCoinbaseAddress struct {
	method abi.Method
}

// we really don't want to change header structure
// therefore we'll encode minGasPrice to extraData parameter
func (uca uncleCoinbaseAddress) run(header *types.Header, arguments ...[]byte) ([]byte, error) {
	if len(arguments) != 1 && len(arguments[0]) != 32 {
		return nil, errBlockHeaderInvalidInput
	}

	index := int(binary.LittleEndian.Uint64(arguments[0]))
	size := getUncleCoinbaseAddressSize(header.Extra)

	if index < 0 || index > size {
		return nil, errBlockHeaderInvalidInput
	}

	hash := header.Extra[len(header.Extra)-index*32-41 : len(header.Extra)-index*32-1]
	// TODO: implement
	//header = bh.getHeader(common.BytesToHash(hash), 0)
	//if header == nil {
	//	return nil, errBlockHeaderInvalidInput
	//}

	return uca.method.Outputs.Pack(hash)
}

func getMergedMiningTagsTotalSize(data []byte) int {
	mergedMiningTagsSize := getMergedMiningTagsSize(data)
	size := getMinGasPriceSizeTotal(data)

	return size + 8 + mergedMiningTagsSize
}

func getMergedMiningTagsSize(data []byte) int {
	size := getMinGasPriceSizeTotal(data)
	sizeBytes := data[len(data)-size-9 : len(data)-size-1]
	return int(binary.LittleEndian.Uint64(sizeBytes))
}

func getMinGasPriceSizeTotal(data []byte) int {
	return getUncleCoinbaseAddressSize(data) + 32
}

func getUncleCoinbaseAddressSizeTotal(data []byte) int {
	size := getUncleCoinbaseAddressSize(data)
	return size + size*32
}

func getUncleCoinbaseAddressSize(data []byte) int {
	sizeBytes := data[len(data)-9 : len(data)-1]
	return int(binary.LittleEndian.Uint64(sizeBytes))
}

func (bh blockHeader) getFunction(input []byte) (BlockHeaderContract, bool) {
	var signature [4]byte
	copy(signature[:], input[:4])

	if function, ok := bh.functions[signature]; !ok {
		return nil, false
	} else {
		return function, ok
	}
}

func signature(rawName string, types []string) (res [4]byte) {
	sig := fmt.Sprintf("%v(%v)", rawName, strings.Join(types, ","))
	id := crypto.Keccak256([]byte(sig))[:4]
	copy(res[:], id)
	return
}

var (
	errHDWalletUtilInvalidInputData = errors.New("invalid input data")
)

type hdWalletUtils struct {
	functions map[[4]byte]PrecompiledContract
}

func newHDWalletUtils() hdWalletUtils {
	base58CheckMethod := abi.NewMethod("toBase58Check", "toBase58Check", abi.Function, "", false, false, abi.Arguments{bytesArg, intArg}, abi.Arguments{stringArg})
	deriveExtendedPublicKeyMethod := abi.NewMethod("deriveExtendedPublicKey", "deriveExtendedPublicKey", abi.Function, "", false, false, abi.Arguments{stringArg, stringArg}, abi.Arguments{stringArg})
	extractPublicKeyFromExtendedPublicKeyMethod := abi.NewMethod("extractPublicKeyFromExtendedPublicKey", "extractPublicKeyFromExtendedPublicKey", abi.Function, "", false, false, abi.Arguments{stringArg}, abi.Arguments{bytesArg})
	getMultisigScriptHashMethod := abi.NewMethod("getMultisigScriptHash", "getMultisigScriptHash", abi.Function, "", false, false, abi.Arguments{intArg, bytesArrArg}, abi.Arguments{bytesArg})

	return hdWalletUtils{
		functions: map[[4]byte]PrecompiledContract{
			signatureFromID(base58CheckMethod.ID):                           &base58Check{base58CheckMethod},
			signatureFromID(deriveExtendedPublicKeyMethod.ID):               &deriveExtendedPublicKey{deriveExtendedPublicKeyMethod},
			signatureFromID(extractPublicKeyFromExtendedPublicKeyMethod.ID): &extractPublicKeyFromExtendedPublicKey{extractPublicKeyFromExtendedPublicKeyMethod},
			signatureFromID(getMultisigScriptHashMethod.ID):                 &getMultisigScriptHash{getMultisigScriptHashMethod},
		},
	}
}

func (hdwu hdWalletUtils) RequiredGas(input []byte) uint64 {
	precompiled, ok := hdwu.getFunction(input)
	if !ok {
		return 0
	}

	return precompiled.RequiredGas(input)
}

func (hdwu hdWalletUtils) Run(input []byte) ([]byte, error) {
	precompiled, ok := hdwu.getFunction(input)
	if !ok {
		return nil, errHDWalletUtilInvalidInputData
	}

	return precompiled.Run(input)
}

type base58Check struct {
	method abi.Method
}

func (b base58Check) RequiredGas(input []byte) uint64 {
	return 13000
}

func (b base58Check) Run(input []byte) ([]byte, error) {
	if len(input) != 64 {
		return nil, errHDWalletUtilInvalidInputData
	}

	args, err := b.method.Inputs.Unpack(input)
	if err != nil {
		return nil, errHDWalletUtilInvalidInputData
	}

	var hash []byte
	if _, ok := args[0].([]byte); !ok {
		return nil, errHDWalletUtilInvalidInputData
	}

	hash = args[0].([]byte)
	if len(hash) != 20 {
		return nil, errHDWalletUtilInvalidInputData
	}

	if _, ok := args[1].(*big.Int); !ok {
		return nil, errHDWalletUtilInvalidInputData
	}

	version := args[1].(big.Int)
	if !version.IsInt64() || version.Int64() < 0 || version.Int64() >= 256 {
		return nil, errHDWalletUtilInvalidInputData
	}

	return []byte(base58.CheckEncode(hash, byte(version.Int64()))), nil
}

type deriveExtendedPublicKey struct {
	method abi.Method
}

func (d deriveExtendedPublicKey) RequiredGas(input []byte) uint64 {
	return 107000
}

func (d deriveExtendedPublicKey) Run(input []byte) ([]byte, error) {
	//args, err := d.method.Inputs.Unpack(input)
	//if err != nil {
	//	return nil, errHDWalletUtilInvalidInputData
	//}

	//xpub := args[0].(string)
	//path := args[1].(string)
	//
	//
	//base58.CheckDecode(xpub)
	return nil, nil
}

type extractPublicKeyFromExtendedPublicKey struct {
	method abi.Method
}

func (e extractPublicKeyFromExtendedPublicKey) RequiredGas(input []byte) uint64 {
	return 11300
}

func (e extractPublicKeyFromExtendedPublicKey) Run(input []byte) ([]byte, error) {
	return nil, nil
}

type getMultisigScriptHash struct {
	method abi.Method
}

func (g getMultisigScriptHash) RequiredGas(input []byte) uint64 {
	// TODO: calculate gas
	return 0
}

func (g getMultisigScriptHash) Run(input []byte) ([]byte, error) {
	return nil, nil
}

func (hdwu hdWalletUtils) getFunction(input []byte) (PrecompiledContract, bool) {
	var signature [4]byte
	copy(signature[:], input[:4])

	if function, ok := hdwu.functions[signature]; !ok {
		return nil, false
	} else {
		return function, ok
	}
}

func signatureFromID(id []byte) (signature [4]byte) {
	copy(signature[:], id[:4])
	return
}
