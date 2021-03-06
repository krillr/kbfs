// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libkbfs

import (
	"fmt"

	"github.com/keybase/client/go/libkb"
	keybase1 "github.com/keybase/client/go/protocol"
)

// ErrorFile is the name of the virtual file in KBFS that should
// contain the last reported error(s).
var ErrorFile = ".kbfs_error"

// WrapError simply wraps an error in a fmt.Stringer interface, so
// that it can be reported.
type WrapError struct {
	Err error
}

// String implements the fmt.Stringer interface for WrapError
func (e WrapError) String() string {
	return e.Err.Error()
}

// NameExistsError indicates that the user tried to create an entry
// for a name that already existed in a subdirectory.
type NameExistsError struct {
	Name string
}

// Error implements the error interface for NameExistsError
func (e NameExistsError) Error() string {
	return fmt.Sprintf("%s already exists", e.Name)
}

// NoSuchNameError indicates that the user tried to access a
// subdirectory entry that doesn't exist.
type NoSuchNameError struct {
	Name string
}

// Error implements the error interface for NoSuchNameError
func (e NoSuchNameError) Error() string {
	return fmt.Sprintf("%s doesn't exist", e.Name)
}

// NoSuchUserError indicates that the given user couldn't be resolved.
type NoSuchUserError struct {
	Input string
}

// Error implements the error interface for NoSuchUserError
func (e NoSuchUserError) Error() string {
	return fmt.Sprintf("%s is not a Keybase user", e.Input)
}

// ToStatus implements the keybase1.ToStatusAble interface for NoSuchUserError
func (e NoSuchUserError) ToStatus() keybase1.Status {
	return keybase1.Status{
		Name: "NotFound",
		Code: int(keybase1.StatusCode_SCNotFound),
		Desc: e.Error(),
	}
}

// BadTLFNameError indicates a top-level folder name that has an
// incorrect format.
type BadTLFNameError struct {
	Name string
}

// Error implements the error interface for BadTLFNameError.
func (e BadTLFNameError) Error() string {
	return fmt.Sprintf("TLF name %s is in an incorrect format", e.Name)
}

// InvalidBlockRefError indicates an invalid block reference was
// encountered.
type InvalidBlockRefError struct {
	ref blockRef
}

func (e InvalidBlockRefError) Error() string {
	return fmt.Sprintf("Invalid block ref %s", e.ref)
}

// InvalidPathError indicates an invalid path was encountered.
type InvalidPathError struct {
	p path
}

// Error implements the error interface for InvalidPathError.
func (e InvalidPathError) Error() string {
	return fmt.Sprintf("Invalid path %s", e.p.DebugString())
}

// InvalidParentPathError indicates a path without a valid parent was
// encountered.
type InvalidParentPathError struct {
	p path
}

// Error implements the error interface for InvalidParentPathError.
func (e InvalidParentPathError) Error() string {
	return fmt.Sprintf("Path with invalid parent %s", e.p.DebugString())
}

// DirNotEmptyError indicates that the user tried to unlink a
// subdirectory that was not empty.
type DirNotEmptyError struct {
	Name string
}

// Error implements the error interface for DirNotEmptyError
func (e DirNotEmptyError) Error() string {
	return fmt.Sprintf("Directory %s is not empty and can't be removed", e.Name)
}

// TlfAccessError that the user tried to perform an unpermitted
// operation on a top-level folder.
type TlfAccessError struct {
	ID TlfID
}

// Error implements the error interface for TlfAccessError
func (e TlfAccessError) Error() string {
	return fmt.Sprintf("Operation not permitted on folder %s", e.ID)
}

// RenameAcrossDirsError indicates that the user tried to do an atomic
// rename across directories.
type RenameAcrossDirsError struct {
}

// Error implements the error interface for RenameAcrossDirsError
func (e RenameAcrossDirsError) Error() string {
	return fmt.Sprintf("Cannot rename across directories")
}

// ErrorFileAccessError indicates that the user tried to perform an
// operation on the ErrorFile that is not allowed.
type ErrorFileAccessError struct {
}

// Error implements the error interface for ErrorFileAccessError
func (e ErrorFileAccessError) Error() string {
	return fmt.Sprintf("Operation not allowed on file %s", ErrorFile)
}

// ReadAccessError indicates that the user tried to read from a
// top-level folder without read permission.
type ReadAccessError struct {
	User   libkb.NormalizedUsername
	Tlf    CanonicalTlfName
	Public bool
}

// Error implements the error interface for ReadAccessError
func (e ReadAccessError) Error() string {
	return fmt.Sprintf("%s does not have read access to directory %s",
		e.User, buildCanonicalPath(e.Public, e.Tlf))
}

// WriteAccessError indicates that the user tried to read from a
// top-level folder without read permission.
type WriteAccessError struct {
	User   libkb.NormalizedUsername
	Tlf    CanonicalTlfName
	Public bool
}

// Error implements the error interface for WriteAccessError
func (e WriteAccessError) Error() string {
	return fmt.Sprintf("%s does not have write access to directory %s",
		e.User, buildCanonicalPath(e.Public, e.Tlf))
}

// NewReadAccessError constructs a ReadAccessError for the given
// directory and user.
func NewReadAccessError(h *TlfHandle, username libkb.NormalizedUsername) error {
	tlfname := h.GetCanonicalName()
	return ReadAccessError{username, tlfname, h.IsPublic()}
}

// NewWriteAccessError constructs a WriteAccessError for the given
// directory and user.
func NewWriteAccessError(h *TlfHandle, username libkb.NormalizedUsername) error {
	tlfname := h.GetCanonicalName()
	return WriteAccessError{username, tlfname, h.IsPublic()}
}

// NeedSelfRekeyError indicates that the folder in question needs to
// be rekeyed for the local device, and can be done so by one of the
// other user's devices.
type NeedSelfRekeyError struct {
	Tlf CanonicalTlfName
}

// Error implements the error interface for NeedSelfRekeyError
func (e NeedSelfRekeyError) Error() string {
	return fmt.Sprintf("This device does not yet have read access to "+
		"directory %s, log into Keybase from one of your other "+
		"devices to grant access", buildCanonicalPath(false, e.Tlf))
}

// NeedOtherRekeyError indicates that the folder in question needs to
// be rekeyed for the local device, and can only done so by one of the
// other users.
type NeedOtherRekeyError struct {
	Tlf CanonicalTlfName
}

// Error implements the error interface for NeedOtherRekeyError
func (e NeedOtherRekeyError) Error() string {
	return fmt.Sprintf("This device does not yet have read access to "+
		"directory %s, ask one of the other directory participants to "+
		"log into Keybase to grant you access automatically",
		buildCanonicalPath(false, e.Tlf))
}

// NotFileBlockError indicates that a file block was expected but a
// block of a different type was found.
//
// ptr and branch should be filled in, but p may be empty.
type NotFileBlockError struct {
	ptr    BlockPointer
	branch BranchName
	p      path
}

func (e NotFileBlockError) Error() string {
	return fmt.Sprintf("The block at %s is not a file block (branch=%s, path=%s)", e.ptr, e.branch, e.p)
}

// NotDirBlockError indicates that a file block was expected but a
// block of a different type was found.
//
// ptr and branch should be filled in, but p may be empty.
type NotDirBlockError struct {
	ptr    BlockPointer
	branch BranchName
	p      path
}

func (e NotDirBlockError) Error() string {
	return fmt.Sprintf("The block at %s is not a dir block (branch=%s, path=%s)", e.ptr, e.branch, e.p)
}

// NotFileError indicates that the user tried to perform a
// file-specific operation on something that isn't a file.
type NotFileError struct {
	path path
}

// Error implements the error interface for NotFileError
func (e NotFileError) Error() string {
	return fmt.Sprintf("%s is not a file (folder %s)", e.path, e.path.Tlf)
}

// NotDirError indicates that the user tried to perform a
// dir-specific operation on something that isn't a directory.
type NotDirError struct {
	path path
}

// Error implements the error interface for NotDirError
func (e NotDirError) Error() string {
	return fmt.Sprintf("%s is not a directory (folder %s)", e.path, e.path.Tlf)
}

// BlockDecodeError indicates that a block couldn't be decoded as
// expected; probably it is the wrong type.
type BlockDecodeError struct {
	decodeErr error
}

// Error implements the error interface for BlockDecodeError
func (e BlockDecodeError) Error() string {
	return fmt.Sprintf("Decode error for a block: %v", e.decodeErr)
}

// BadDataError indicates that KBFS is storing corrupt data for a block.
type BadDataError struct {
	ID BlockID
}

// Error implements the error interface for BadDataError
func (e BadDataError) Error() string {
	return fmt.Sprintf("Bad data for block %v", e.ID)
}

// NoSuchBlockError indicates that a block for the associated ID doesn't exist.
type NoSuchBlockError struct {
	ID BlockID
}

// Error implements the error interface for NoSuchBlockError
func (e NoSuchBlockError) Error() string {
	return fmt.Sprintf("Couldn't get block %v", e.ID)
}

// BadCryptoError indicates that KBFS performed a bad crypto operation.
type BadCryptoError struct {
	ID BlockID
}

// Error implements the error interface for BadCryptoError
func (e BadCryptoError) Error() string {
	return fmt.Sprintf("Bad crypto for block %v", e.ID)
}

// BadCryptoMDError indicates that KBFS performed a bad crypto
// operation, specifically on a MD object.
type BadCryptoMDError struct {
	ID TlfID
}

// Error implements the error interface for BadCryptoMDError
func (e BadCryptoMDError) Error() string {
	return fmt.Sprintf("Bad crypto for the metadata of directory %v", e.ID)
}

// BadMDError indicates that the system is storing corrupt MD object
// for the given TLF ID.
type BadMDError struct {
	ID TlfID
}

// Error implements the error interface for BadMDError
func (e BadMDError) Error() string {
	return fmt.Sprintf("Wrong format for metadata for directory %v", e.ID)
}

// MDMissingDataError indicates that we are trying to take get the
// metadata ID of a MD object with no serialized data field.
type MDMissingDataError struct {
	ID TlfID
}

// Error implements the error interface for MDMissingDataError
func (e MDMissingDataError) Error() string {
	return fmt.Sprintf("No serialized private data in the metadata "+
		"for directory %v", e.ID)
}

// MDMismatchError indicates an inconsistent or unverifiable MD object
// for the given top-level folder.
type MDMismatchError struct {
	Dir string
	Err error
}

// Error implements the error interface for MDMismatchError
func (e MDMismatchError) Error() string {
	return fmt.Sprintf("Could not verify metadata for directory %s: %s",
		e.Dir, e.Err)
}

// NoSuchMDError indicates that there is no MD object for the given
// folder, revision, and merged status.
type NoSuchMDError struct {
	Tlf TlfID
	Rev MetadataRevision
	BID BranchID
}

// Error implements the error interface for NoSuchMDError
func (e NoSuchMDError) Error() string {
	return fmt.Sprintf("Couldn't get metadata for folder %v, revision %d, "+
		"%s", e.Tlf, e.Rev, e.BID)
}

// InvalidMetadataVersionError indicates that an invalid metadata version was
// used.
type InvalidMetadataVersionError struct {
	Tlf         TlfID
	MetadataVer MetadataVer
}

// Error implements the error interface for InvalidMetadataVersionError.
func (e InvalidMetadataVersionError) Error() string {
	return fmt.Sprintf("Invalid metadata version %d for folder %s",
		int(e.MetadataVer), e.Tlf)
}

// NewMetadataVersionError indicates that the metadata for the given
// folder has been written using a new metadata version that our
// client doesn't understand.
type NewMetadataVersionError struct {
	Tlf         TlfID
	MetadataVer MetadataVer
}

// Error implements the error interface for NewMetadataVersionError.
func (e NewMetadataVersionError) Error() string {
	return fmt.Sprintf(
		"The metadata for folder %s is of a version (%d) that we can't read",
		e.Tlf, e.MetadataVer)
}

// InvalidDataVersionError indicates that an invalid data version was
// used.
type InvalidDataVersionError struct {
	DataVer DataVer
}

// Error implements the error interface for InvalidDataVersionError.
func (e InvalidDataVersionError) Error() string {
	return fmt.Sprintf("Invalid data version %d", int(e.DataVer))
}

// NewDataVersionError indicates that the data at the given path has
// been written using a new data version that our client doesn't
// understand.
type NewDataVersionError struct {
	path    path
	DataVer DataVer
}

// Error implements the error interface for NewDataVersionError.
func (e NewDataVersionError) Error() string {
	return fmt.Sprintf(
		"The data at path %s is of a version (%d) that we can't read "+
			"(in folder %s)",
		e.path, e.DataVer, e.path.Tlf)
}

// OutdatedVersionError indicates that we have encountered some new
// data version we don't understand, and the user should be prompted
// to upgrade.
type OutdatedVersionError struct {
}

// Error implements the error interface for OutdatedVersionError.
func (e OutdatedVersionError) Error() string {
	return "Your software is out of date, and cannot read this data.  " +
		"Please use `keybase update check` to upgrade your software."
}

// InvalidKeyGenerationError indicates that an invalid key generation
// was used.
type InvalidKeyGenerationError struct {
	TlfID  TlfID
	KeyGen KeyGen
}

// Error implements the error interface for InvalidKeyGenerationError.
func (e InvalidKeyGenerationError) Error() string {
	return fmt.Sprintf("Invalid key generation %d for %s", int(e.KeyGen), e.TlfID)
}

// NewKeyGenerationError indicates that the data at the given path has
// been written using keys that our client doesn't have.
type NewKeyGenerationError struct {
	TlfID  TlfID
	KeyGen KeyGen
}

// Error implements the error interface for NewKeyGenerationError.
func (e NewKeyGenerationError) Error() string {
	return fmt.Sprintf(
		"The data for %v is keyed with a key generation (%d) that "+
			"we don't know", e.TlfID, e.KeyGen)
}

// BadSplitError indicates that the BlockSplitter has an error.
type BadSplitError struct {
}

// Error implements the error interface for BadSplitError
func (e BadSplitError) Error() string {
	return "Unexpected bad block split"
}

// TooLowByteCountError indicates that size of a block is smaller than
// the expected size.
type TooLowByteCountError struct {
	ExpectedMinByteCount int
	ByteCount            int
}

// Error implements the error interface for TooLowByteCountError
func (e TooLowByteCountError) Error() string {
	return fmt.Sprintf("Expected at least %d bytes, got %d bytes",
		e.ExpectedMinByteCount, e.ByteCount)
}

// InconsistentEncodedSizeError is raised when a dirty block has a
// non-zero encoded size.
type InconsistentEncodedSizeError struct {
	info BlockInfo
}

// Error implements the error interface for InconsistentEncodedSizeError
func (e InconsistentEncodedSizeError) Error() string {
	return fmt.Sprintf("Block pointer to dirty block %v with non-zero "+
		"encoded size = %d bytes", e.info.ID, e.info.EncodedSize)
}

// MDWriteNeededInRequest indicates that the system needs MD write
// permissions to successfully complete an operation, so it should
// retry in mdWrite mode.
type MDWriteNeededInRequest struct {
}

// Error implements the error interface for MDWriteNeededInRequest
func (e MDWriteNeededInRequest) Error() string {
	return "This request needs MD write access, but doesn't have it."
}

// UnknownSigVer indicates that we can't process a signature because
// it has an unknown version.
type UnknownSigVer struct {
	sigVer SigVer
}

// Error implements the error interface for UnknownSigVer
func (e UnknownSigVer) Error() string {
	return fmt.Sprintf("Unknown signature version %d", int(e.sigVer))
}

// KeyNotFoundError indicates that a key matching the given KID
// couldn't be found.
type KeyNotFoundError struct {
	kid keybase1.KID
}

// Error implements the error interface for KeyNotFoundError.
func (e KeyNotFoundError) Error() string {
	return fmt.Sprintf("Could not find key with kid=%s", e.kid)
}

// UnverifiableTlfUpdateError indicates that a MD update could not be
// verified.
type UnverifiableTlfUpdateError struct {
	Tlf  string
	User libkb.NormalizedUsername
	Err  error
}

// Error implements the error interface for UnverifiableTlfUpdateError.
func (e UnverifiableTlfUpdateError) Error() string {
	return fmt.Sprintf("%s was last written by an unknown device claiming "+
		"to belong to user %s.  The device has possibly been revoked by the "+
		"user.  Use `keybase log send` to file an issue with the Keybase "+
		"admins.", e.Tlf, e.User)
}

// KeyCacheMissError indicates that a key matching the given TlfID
// and key generation wasn't found in cache.
type KeyCacheMissError struct {
	tlf    TlfID
	keyGen KeyGen
}

// Error implements the error interface for KeyCacheMissError.
func (e KeyCacheMissError) Error() string {
	return fmt.Sprintf("Could not find key with tlf=%s, keyGen=%d", e.tlf, e.keyGen)
}

// KeyCacheHitError indicates that a key matching the given TlfID
// and key generation was found in cache but the object type was unknown.
type KeyCacheHitError struct {
	tlf    TlfID
	keyGen KeyGen
}

// Error implements the error interface for KeyCacheHitError.
func (e KeyCacheHitError) Error() string {
	return fmt.Sprintf("Invalid key with tlf=%s, keyGen=%d", e.tlf, e.keyGen)
}

// UnexpectedShortCryptoRandRead indicates that fewer bytes were read
// from crypto.rand.Read() than expected.
type UnexpectedShortCryptoRandRead struct {
}

// Error implements the error interface for UnexpectedShortRandRead.
func (e UnexpectedShortCryptoRandRead) Error() string {
	return "Unexpected short read from crypto.rand.Read()"
}

// UnknownEncryptionVer indicates that we can't decrypt an
// encryptedData object because it has an unknown version.
type UnknownEncryptionVer struct {
	ver EncryptionVer
}

// Error implements the error interface for UnknownEncryptionVer.
func (e UnknownEncryptionVer) Error() string {
	return fmt.Sprintf("Unknown encryption version %d", int(e.ver))
}

// InvalidNonceError indicates that an invalid cryptographic nonce was
// detected.
type InvalidNonceError struct {
	nonce []byte
}

// Error implements the error interface for InvalidNonceError.
func (e InvalidNonceError) Error() string {
	return fmt.Sprintf("Invalid nonce %v", e.nonce)
}

// NoKeysError indicates that no keys were provided for a decryption allowing
// multiple device keys
type NoKeysError struct{}

func (e NoKeysError) Error() string {
	return "No keys provided"
}

// InvalidPublicTLFOperation indicates that an invalid operation was
// attempted on a public TLF.
type InvalidPublicTLFOperation struct {
	id     TlfID
	opName string
}

// Error implements the error interface for InvalidPublicTLFOperation.
func (e InvalidPublicTLFOperation) Error() string {
	return fmt.Sprintf("Tried to do invalid operation %s on public TLF %v",
		e.opName, e.id)
}

// WrongOpsError indicates that an unexpected path got passed into a
// FolderBranchOps instance
type WrongOpsError struct {
	nodeFB FolderBranch
	opsFB  FolderBranch
}

// Error implements the error interface for WrongOpsError.
func (e WrongOpsError) Error() string {
	return fmt.Sprintf("Ops for folder %v, branch %s, was given path %s, "+
		"branch %s", e.opsFB.Tlf, e.opsFB.Branch, e.nodeFB.Tlf, e.nodeFB.Branch)
}

// NodeNotFoundError indicates that we tried to find a node for the
// given BlockPointer and failed.
type NodeNotFoundError struct {
	ptr BlockPointer
}

// Error implements the error interface for NodeNotFoundError.
func (e NodeNotFoundError) Error() string {
	return fmt.Sprintf("No node found for pointer %v", e.ptr)
}

// ParentNodeNotFoundError indicates that we tried to update a Node's
// parent with a BlockPointer that we don't yet know about.
type ParentNodeNotFoundError struct {
	parent blockRef
}

// Error implements the error interface for ParentNodeNotFoundError.
func (e ParentNodeNotFoundError) Error() string {
	return fmt.Sprintf("No such parent node found for %v", e.parent)
}

// EmptyNameError indicates that the user tried to use an empty name
// for the given blockRef.
type EmptyNameError struct {
	ref blockRef
}

// Error implements the error interface for EmptyNameError.
func (e EmptyNameError) Error() string {
	return fmt.Sprintf("Cannot use empty name for %v", e.ref)
}

// PaddedBlockReadError occurs if the number of bytes read do not
// equal the number of bytes specified.
type PaddedBlockReadError struct {
	ActualLen   int
	ExpectedLen int
}

// Error implements the error interface of PaddedBlockReadError.
func (e PaddedBlockReadError) Error() string {
	return fmt.Sprintf("Reading block data out of padded block resulted in %d bytes, expected %d",
		e.ActualLen, e.ExpectedLen)
}

// NotDirectFileBlockError indicates that a direct file block was
// expected, but something else (e.g., an indirect file block) was
// given instead.
type NotDirectFileBlockError struct {
}

func (e NotDirectFileBlockError) Error() string {
	return fmt.Sprintf("Unexpected block type; expected a direct file block")
}

// KeyHalfMismatchError is returned when the key server doesn't return the expected key half.
type KeyHalfMismatchError struct {
	Expected TLFCryptKeyServerHalfID
	Actual   TLFCryptKeyServerHalfID
}

// Error implements the error interface for KeyHalfMismatchError.
func (e KeyHalfMismatchError) Error() string {
	return fmt.Sprintf("Key mismatch, expected ID: %s, actual ID: %s",
		e.Expected, e.Actual)
}

// InvalidHashError is returned whenever an invalid hash is
// detected.
type InvalidHashError struct {
	H Hash
}

func (e InvalidHashError) Error() string {
	return fmt.Sprintf("Invalid hash %s", e.H)
}

// InvalidTlfID indicates whether the TLF ID string is not parseable
// or invalid.
type InvalidTlfID struct {
	id string
}

func (e InvalidTlfID) Error() string {
	return fmt.Sprintf("Invalid TLF ID %q", e.id)
}

// UnknownHashTypeError is returned whenever a hash with an unknown
// hash type is attempted to be used for verification.
type UnknownHashTypeError struct {
	T HashType
}

func (e UnknownHashTypeError) Error() string {
	return fmt.Sprintf("Unknown hash type %s", e.T)
}

// HashMismatchError is returned whenever a hash mismatch is detected.
type HashMismatchError struct {
	ExpectedH Hash
	ActualH   Hash
}

func (e HashMismatchError) Error() string {
	return fmt.Sprintf("Hash mismatch: expected %s, got %s",
		e.ExpectedH, e.ActualH)
}

// MDServerDisconnected indicates the MDServer has been disconnected for clients waiting
// on an update channel.
type MDServerDisconnected struct {
}

// Error implements the error interface for MDServerDisconnected.
func (e MDServerDisconnected) Error() string {
	return "MDServer is disconnected"
}

// MDRevisionMismatch indicates that we tried to apply a revision that
// was not the next in line.
type MDRevisionMismatch struct {
	rev  MetadataRevision
	curr MetadataRevision
}

// Error implements the error interface for MDRevisionMismatch.
func (e MDRevisionMismatch) Error() string {
	return fmt.Sprintf("MD revision %d isn't next in line for our "+
		"current revision %d", e.rev, e.curr)
}

// MDTlfIDMismatch indicates that the ID field of a successor MD
// doesn't match the ID field of its predecessor.
type MDTlfIDMismatch struct {
	currID TlfID
	nextID TlfID
}

func (e MDTlfIDMismatch) Error() string {
	return fmt.Sprintf("TLF ID %s doesn't match successor TLF ID %s",
		e.currID, e.nextID)
}

// MDPrevRootMismatch indicates that the PrevRoot field of a successor
// MD doesn't match the metadata ID of its predecessor.
type MDPrevRootMismatch struct {
	prevRoot         MdID
	expectedPrevRoot MdID
}

func (e MDPrevRootMismatch) Error() string {
	return fmt.Sprintf("PrevRoot %s doesn't match expected %s",
		e.prevRoot, e.expectedPrevRoot)
}

// MDDiskUsageMismatch indicates an inconsistency in the DiskUsage
// field of a RootMetadata object.
type MDDiskUsageMismatch struct {
	expectedDiskUsage uint64
	actualDiskUsage   uint64
}

func (e MDDiskUsageMismatch) Error() string {
	return fmt.Sprintf("Disk usage %d doesn't match expected %d",
		e.actualDiskUsage, e.expectedDiskUsage)
}

// MDUpdateInvertError indicates that we tried to apply a revision that
// was not the next in line.
type MDUpdateInvertError struct {
	rev  MetadataRevision
	curr MetadataRevision
}

// Error implements the error interface for MDUpdateInvertError.
func (e MDUpdateInvertError) Error() string {
	return fmt.Sprintf("MD revision %d isn't next in line for our "+
		"current revision %d while inverting", e.rev, e.curr)
}

// NotPermittedWhileDirtyError indicates that some operation failed
// because of outstanding dirty files, and may be retried later.
type NotPermittedWhileDirtyError struct {
}

// Error implements the error interface for NotPermittedWhileDirtyError.
func (e NotPermittedWhileDirtyError) Error() string {
	return "Not permitted while writes are dirty"
}

// NoChainFoundError indicates that a conflict resolution chain
// corresponding to the given pointer could not be found.
type NoChainFoundError struct {
	ptr BlockPointer
}

// Error implements the error interface for NoChainFoundError.
func (e NoChainFoundError) Error() string {
	return fmt.Sprintf("No chain found for %v", e.ptr)
}

// DisallowedPrefixError indicates that the user attempted to create
// an entry using a name with a disallowed prefix.
type DisallowedPrefixError struct {
	name   string
	prefix string
}

// Error implements the error interface for NoChainFoundError.
func (e DisallowedPrefixError) Error() string {
	return fmt.Sprintf("Cannot create %s because it has the prefix %s",
		e.name, e.prefix)
}

// FileTooBigError indicates that the user tried to write a file that
// would be bigger than KBFS's supported size.
type FileTooBigError struct {
	p               path
	size            int64
	maxAllowedBytes uint64
}

// Error implements the error interface for FileTooBigError.
func (e FileTooBigError) Error() string {
	return fmt.Sprintf("File %s would have increased to %d bytes, which is "+
		"over the supported limit of %d bytes", e.p, e.size, e.maxAllowedBytes)
}

// NameTooLongError indicates that the user tried to write a directory
// entry name that would be bigger than KBFS's supported size.
type NameTooLongError struct {
	name            string
	maxAllowedBytes uint32
}

// Error implements the error interface for NameTooLongError.
func (e NameTooLongError) Error() string {
	return fmt.Sprintf("New directory entry name %s has more than the maximum "+
		"allowed number of bytes (%d)", e.name, e.maxAllowedBytes)
}

// DirTooBigError indicates that the user tried to write a directory
// that would be bigger than KBFS's supported size.
type DirTooBigError struct {
	p               path
	size            uint64
	maxAllowedBytes uint64
}

// Error implements the error interface for DirTooBigError.
func (e DirTooBigError) Error() string {
	return fmt.Sprintf("Directory %s would have increased to at least %d "+
		"bytes, which is over the supported limit of %d bytes", e.p,
		e.size, e.maxAllowedBytes)
}

// TlfNameNotCanonical indicates that a name isn't a canonical, and
// that another (not necessarily canonical) name should be tried.
type TlfNameNotCanonical struct {
	Name, NameToTry string
}

func (e TlfNameNotCanonical) Error() string {
	return fmt.Sprintf("TLF name %s isn't canonical: try %s instead",
		e.Name, e.NameToTry)
}

// NoCurrentSessionError indicates that the daemon has no current
// session.  This is basically a wrapper for session.ErrNoSession,
// needed to give the correct return error code to the OS.
type NoCurrentSessionError struct {
}

// Error implements the error interface for NoCurrentSessionError.
func (e NoCurrentSessionError) Error() string {
	return "You are not logged into Keybase.  Try `keybase login`."
}

// NoCurrentSessionExpectedError is the error text that will get
// converted into a NoCurrentSessionError.
var NoCurrentSessionExpectedError = "no current session"

// RekeyPermissionError indicates that the user tried to rekey a
// top-level folder in a manner inconsistent with their permissions.
type RekeyPermissionError struct {
	User libkb.NormalizedUsername
	Dir  string
}

// Error implements the error interface for RekeyPermissionError
func (e RekeyPermissionError) Error() string {
	return fmt.Sprintf("%s is trying to rekey directory %s in a manner "+
		"inconsistent with their role", e.User, e.Dir)
}

// NewRekeyPermissionError constructs a RekeyPermissionError for the given
// directory and user.
func NewRekeyPermissionError(
	dir *TlfHandle, username libkb.NormalizedUsername) error {
	dirname := dir.GetCanonicalPath()
	return RekeyPermissionError{username, dirname}
}

// RekeyIncompleteError is returned when a rekey is partially done but
// needs a writer to finish it.
type RekeyIncompleteError struct{}

func (e RekeyIncompleteError) Error() string {
	return fmt.Sprintf("Rekey did not complete due to insufficient user permissions")
}

// InvalidKIDError is returned whenever an invalid KID is detected.
type InvalidKIDError struct {
	kid keybase1.KID
}

func (e InvalidKIDError) Error() string {
	return fmt.Sprintf("Invalid KID %s", e.kid)
}

// InvalidByte32DataError is returned whenever invalid data for a
// 32-byte type is detected.
type InvalidByte32DataError struct {
	data []byte
}

func (e InvalidByte32DataError) Error() string {
	return fmt.Sprintf("Invalid byte32 data %v", e.data)
}

// TimeoutError is just a replacement for context.DeadlineExceeded
// with a more friendly error string.
type TimeoutError struct {
}

func (e TimeoutError) Error() string {
	return "Operation timed out"
}

// InvalidOpError is returned when an operation is called that isn't supported
// by the current implementation.
type InvalidOpError struct {
	op string
}

func (e InvalidOpError) Error() string {
	return fmt.Sprintf("Invalid operation: %s", e.op)
}

// CRAbandonStagedBranchError indicates that conflict resolution had to
// abandon a staged branch due to an unresolvable error.
type CRAbandonStagedBranchError struct {
	Err error
	Bid BranchID
}

func (e CRAbandonStagedBranchError) Error() string {
	return fmt.Sprintf("Abandoning staged branch %s due to an error: %v",
		e.Bid, e.Err)
}

// NoSuchFolderListError indicates that the user tried to access a
// subdirectory of /keybase that doesn't exist.
type NoSuchFolderListError struct {
	Name     string
	PrivName string
	PubName  string
}

// Error implements the error interface for NoSuchFolderListError
func (e NoSuchFolderListError) Error() string {
	return fmt.Sprintf("/keybase/%s is not a Keybase folder.  "+
		"All folders begin with /keybase/%s or /keybase/%s.",
		e.Name, e.PrivName, e.PubName)
}

// UnexpectedUnmergedPutError indicates that we tried to do an
// unmerged put when that was disallowed.
type UnexpectedUnmergedPutError struct {
}

// Error implements the error interface for UnexpectedUnmergedPutError
func (e UnexpectedUnmergedPutError) Error() string {
	return "Unmerged puts are not allowed"
}

// NoSuchTlfHandleError indicates we were unable to resolve a folder
// ID to a folder handle.
type NoSuchTlfHandleError struct {
	ID TlfID
}

// Error implements the error interface for NoSuchTlfHandleError
func (e NoSuchTlfHandleError) Error() string {
	return fmt.Sprintf("Folder handle for %s not found", e.ID)
}

// TlfHandleExtensionMismatchError indicates the expected extension
// doesn't match the server's extension for the given handle.
type TlfHandleExtensionMismatchError struct {
	Expected TlfHandleExtension
	// Actual may be nil.
	Actual *TlfHandleExtension
}

// Error implements the error interface for TlfHandleExtensionMismatchError
func (e TlfHandleExtensionMismatchError) Error() string {
	return fmt.Sprintf("Folder handle extension mismatch, "+
		"expected: %s, actual: %s", e.Expected, e.Actual)
}

// MetadataIsFinalError indicates that we tried to make or set a
// successor to a finalized folder.
type MetadataIsFinalError struct {
}

// Error implements the error interface for MetadataIsFinalError.
func (e MetadataIsFinalError) Error() string {
	return "Metadata is final"
}

// IncompatibleHandleError indicates that somethine tried to update
// the head of a TLF with a RootMetadata with an incompatible handle.
type IncompatibleHandleError struct {
	oldName                  CanonicalTlfName
	partiallyResolvedOldName CanonicalTlfName
	newName                  CanonicalTlfName
}

func (e IncompatibleHandleError) Error() string {
	return fmt.Sprintf(
		"old head %q resolves to %q instead of new head %q",
		e.oldName, e.partiallyResolvedOldName, e.newName)
}

// ShutdownHappenedError indicates that shutdown has happened.
type ShutdownHappenedError struct {
}

// Error implements the error interface for ShutdownHappenedError.
func (e ShutdownHappenedError) Error() string {
	return "Shutdown happened"
}

// UnmergedError indicates that fbo is on an unmerged local revision
type UnmergedError struct {
}

// Error implements the error interface for UnmergedError.
func (e UnmergedError) Error() string {
	return "fbo is on an unmerged local revision"
}

// ExclOnUnmergedError happens when an operation with O_EXCL set when fbo is on
// an unmerged local revision
type ExclOnUnmergedError struct {
}

// Error implements the error interface for ExclOnUnmergedError.
func (e ExclOnUnmergedError) Error() string {
	return "an operation with O_EXCL set is called but fbo is on an unmerged local version"
}

// OverQuotaWarning indicates that the user is over their quota, and
// is being slowed down by the server.
type OverQuotaWarning struct {
	UsageBytes int64
	LimitBytes int64
}

// Error implements the error interface for OverQuotaWarning.
func (w OverQuotaWarning) Error() string {
	return fmt.Sprintf("You are using %d bytes, and your plan limits you "+
		"to %d bytes.  Please delete some data.", w.UsageBytes, w.LimitBytes)
}

// OpsCantHandleFavorite means that folderBranchOps wasn't able to
// deal with a favorites request.
type OpsCantHandleFavorite struct {
	Msg string
}

// Error implements the error interface for OpsCantHandleFavorite.
func (e OpsCantHandleFavorite) Error() string {
	return fmt.Sprintf("Couldn't handle the favorite operation: %s", e.Msg)
}

// TlfHandleFinalizedError is returned when something attempts to modify
// a finalized TLF handle.
type TlfHandleFinalizedError struct {
}

// Error implements the error interface for TlfHandleFinalizedError.
func (e TlfHandleFinalizedError) Error() string {
	return "Attempt to modify finalized TLF handle"
}

// NoSigChainError means that a user we were trying to identify does
// not have a sigchain.
type NoSigChainError struct {
	User libkb.NormalizedUsername
}

// Error implements the error interface for NoSigChainError.
func (e NoSigChainError) Error() string {
	return fmt.Sprintf("%s has not yet installed Keybase and set up the "+
		"Keybase filesystem. Please ask them to.", e.User)
}

// RekeyConflictError indicates a conflict happened while trying to rekey.
type RekeyConflictError struct {
	Err error
}

// Error implements the error interface for RekeyConflictError.
func (e RekeyConflictError) Error() string {
	return fmt.Sprintf("Conflict during a rekey, not retrying: %v", e.Err)
}

// UnmergedSelfConflictError indicates that we hit a conflict on the
// unmerged branch, so a previous MD PutUnmerged we thought had
// failed, had actually succeeded.
type UnmergedSelfConflictError struct {
	Err error
}

// Error implements the error interface for UnmergedSelfConflictError.
func (e UnmergedSelfConflictError) Error() string {
	return fmt.Sprintf("Unmerged self conflict: %v", e.Err)
}
