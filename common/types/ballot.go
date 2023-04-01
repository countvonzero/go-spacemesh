package types

import (
	"bytes"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spacemeshos/go-scale"

	"github.com/spacemeshos/go-spacemesh/codec"
	"github.com/spacemeshos/go-spacemesh/hash"
	"github.com/spacemeshos/go-spacemesh/log"
)

const (
	// BallotIDSize in bytes.
	// FIXME(dshulyak) why do we cast to hash32 when returning bytes?
	BallotIDSize = Hash32Length
)

//go:generate scalegen

// BallotID is a 20-byte blake3 sum of the serialized ballot used to identify a Ballot.
type BallotID Hash20

// EmptyBallotID is a canonical empty BallotID.
var EmptyBallotID = BallotID{}

// EncodeScale implements scale codec interface.
func (id *BallotID) EncodeScale(e *scale.Encoder) (int, error) {
	return scale.EncodeByteArray(e, id[:])
}

// DecodeScale implements scale codec interface.
func (id *BallotID) DecodeScale(d *scale.Decoder) (int, error) {
	return scale.DecodeByteArray(d, id[:])
}

// Ballot contains the smeshers signed vote on the mesh history.
type Ballot struct {
	// BallotMetadata is the signed part of the ballot.
	BallotMetadata
	InnerBallot
	// smeshers signature on InnerBallot
	Signature EdSignature
	// Votes field is not signed.
	Votes Votes
	// the proof of the smeshers eligibility to vote and propose block content in this epoch.
	// Eligibilities must be produced in the ascending order.
	// the proofs are vrf signatures and need not be included in the ballot's signature.
	EligibilityProofs []VotingEligibility `scale:"max=500"` // according to protocol there are 50 per layer, the rest is safety margin
	// from the smesher's view, the set of ATXs eligible to vote and propose block content in this epoch
	// only present in smesher's first ballot of the epoch
	ActiveSet []ATXID `scale:"max=100000"`

	// the following fields are kept private and from being serialized
	ballotID BallotID
	// the public key of the smesher used
	smesherID NodeID
	// malicious is set to true if smesher that produced this ballot is known to be malicious.
	malicious bool
}

func (b Ballot) Equal(other Ballot) bool {
	if !cmp.Equal(other.BallotMetadata, b.BallotMetadata) {
		return false
	}
	if !cmp.Equal(other.InnerBallot, b.InnerBallot, cmpopts.EquateEmpty()) {
		return false
	}
	if other.Signature != b.Signature {
		return false
	}
	if !cmp.Equal(other.Votes, b.Votes) {
		return false
	}
	if !cmp.Equal(other.EligibilityProofs, b.EligibilityProofs) {
		return false
	}
	return true
}

// BallotMetadata is the signed part of Ballot.
type BallotMetadata struct {
	// the layer ID in which this ballot is eligible for. this will be validated via EligibilityProof
	Layer LayerID
	// hash of InnerBallot
	MsgHash Hash32
}

func (m *BallotMetadata) MarshalLogObject(encoder log.ObjectEncoder) error {
	encoder.AddUint32("layer", m.Layer.Value)
	encoder.AddString("msgHash", m.MsgHash.String())
	return nil
}

// InnerBallot contains all info about a smeshers votes on the mesh history. this structure is
// serialized and signed to produce the signature in Ballot.
type InnerBallot struct {
	// the smeshers ATX in the epoch this ballot is cast.
	AtxID ATXID
	// OpinionHash is a aggregated opinion on all previous layers.
	// It is included into transferred data explicitly, so that signature
	// can be verified before decoding votes.
	OpinionHash Hash32

	// total number of ballots the smesher is eligible in this epoch.
	EligibilityCount uint32

	// the first Ballot the smesher cast in the epoch. this Ballot is a special Ballot that contains information
	// that cannot be changed mid-epoch.
	RefBallot BallotID
	EpochData *EpochData
}

// Votes is for encoding local votes to send over the wire.
//
// a smesher creates votes in the following steps:
// - select a Ballot in the past as a base Ballot
// - calculate the opinion difference on history between the smesher and the base Ballot
// - encode the opinion difference in 3 list:
//   - ForDiff
//     contains blocks we support while the base ballot did not support (i.e. voted against)
//     for blocks we support in layers later than the base ballot, we also add them to this list
//   - AgainstDiff
//     contains blocks we vote against while the base ballot explicitly supported
//   - NeutralDiff
//     contains layers we vote neutral while the base ballot explicitly supported or voted against
//
// example:
// layer | unified content block
// -----------------------------------------------------------------------------------------------
//
//	N   | UCB_A (genesis)
//
// -----------------------------------------------------------------------------------------------
//
//	N+1  | UCB_B base:UCB_A, for:[UCB_A], against:[], neutral:[]
//
// -----------------------------------------------------------------------------------------------
//
//	N+2  | UCB_C base:UCB_B, for:[UCB_B], against:[], neutral:[]
//
// -----------------------------------------------------------------------------------------------
//
//	(hare hasn't terminated for N+2)
//	N+3  | UCB_D base:UCB_B, for:[UCB_B], against:[], neutral:[N+2]
//
// -----------------------------------------------------------------------------------------------
//
//	(hare succeeded for N+2 but failed for N+3)
//	N+4  | UCB_E base:UCB_C, for:[UCB_C], against:[], neutral:[]
//
// -----------------------------------------------------------------------------------------------
// NOTE on neutral votes: a base block is by default neutral on all blocks and layers that come after it, so
// there's no need to explicitly add neutral votes for more recent layers.
//
// TODO: maybe collapse Support and Against into a single list.
//
//	see https://github.com/spacemeshos/go-spacemesh/issues/2369.
type Votes struct {
	// Base ballot.
	Base BallotID
	// Support block id at a particular layer and height.
	Support []Vote `scale:"max=10000"` // sliding vote window size is 10k layers, vote for one block per layer
	// Against previously supported block.
	Against []Vote `scale:"max=10000"` // sliding vote window size is 10k layers, vote for one block per layer
	// Abstain on layers until they are terminated.
	Abstain []LayerID `scale:"max=10000"` // sliding vote window size is 10k layers, vote to abstain on any layer
}

// MarshalLogObject implements logging interface.
func (v *Votes) MarshalLogObject(encoder log.ObjectEncoder) error {
	encoder.AddString("base", v.Base.String())
	encoder.AddArray("support", log.ArrayMarshalerFunc(func(encoder log.ArrayEncoder) error {
		for _, vote := range v.Support {
			encoder.AppendObject(&vote)
		}
		return nil
	}))
	encoder.AddArray("against", log.ArrayMarshalerFunc(func(encoder log.ArrayEncoder) error {
		for _, vote := range v.Against {
			encoder.AppendObject(&vote)
		}
		return nil
	}))
	encoder.AddArray("abstain", log.ArrayMarshalerFunc(func(encoder log.ArrayEncoder) error {
		for _, lid := range v.Abstain {
			encoder.AppendString(lid.String())
		}
		return nil
	}))
	return nil
}

// Vote additionally carries layer id and height
// in order for the tortoise to count votes without downloading block body.
type Vote struct {
	ID      BlockID
	LayerID LayerID
	Height  uint64
}

// MarshalLogObject implements logging interface.
func (s *Vote) MarshalLogObject(encoder log.ObjectEncoder) error {
	encoder.AddString("id", s.ID.String())
	encoder.AddUint32("layer", s.LayerID.Value)
	encoder.AddUint64("height", s.Height)
	return nil
}

// Opinion is a tuple from opinion hash and votes that decode to opinion hash.
type Opinion struct {
	Hash Hash32
	Votes
}

// MarshalLogObject implements logging interface.
func (o *Opinion) MarshalLogObject(encoder log.ObjectEncoder) error {
	encoder.AddString("hash", o.Hash.String())
	return o.Votes.MarshalLogObject(encoder)
}

// EpochData contains information that cannot be changed mid-epoch.
type EpochData struct {
	ActiveSetHash Hash32
	// the beacon value the smesher recorded for this epoch
	Beacon Beacon
}

// Initialize calculates and sets the Ballot's cached ballotID and smesherID.
// this should be called once all the other fields of the Ballot are set.
func (b *Ballot) Initialize() error {
	if b.ID() != EmptyBallotID {
		return fmt.Errorf("ballot already initialized")
	}
	if b.Signature == EmptyEdSignature {
		return fmt.Errorf("cannot calculate Ballot ID: signature is nil")
	}

	if b.MsgHash != BytesToHash(b.HashInnerBytes()) {
		return fmt.Errorf("bad message hash")
	}

	h := hash.New()
	_, err := codec.EncodeTo(h, &b.InnerBallot)
	if err != nil {
		return fmt.Errorf("failed to encode inner ballot for hashing")
	}
	_, err = scale.EncodeByteSlice(scale.NewEncoder(h), b.Signature[:])
	if err != nil {
		return fmt.Errorf("failed to encode byte slice")
	}
	b.ballotID = BallotID(BytesToHash(h.Sum(nil)).ToHash20())
	return nil
}

// SetMetadata sets BallotMetadata.
func (b *Ballot) SetMetadata() {
	if b.Layer == (LayerID{}) {
		log.Fatal("ballot is missing layer")
	}
	b.MsgHash = BytesToHash(b.HashInnerBytes())
}

// SignedBytes returns the serialization of the BallotMetadata for signing.
func (b *Ballot) SignedBytes() []byte {
	b.SetMetadata()
	data, err := codec.Encode(&b.BallotMetadata)
	if err != nil {
		log.With().Fatal("failed to serialize BallotMetadata", log.Err(err))
	}
	return data
}

// HashInnerBytes returns the hash of the InnerBallot.
func (b *Ballot) HashInnerBytes() []byte {
	h := hash.New()
	_, err := codec.EncodeTo(h, &b.InnerBallot)
	if err != nil {
		log.Fatal("failed to encode InnerBallot for hashing", log.Err(err))
	}
	return h.Sum(nil)
}

// SetID from stored data.
func (b *Ballot) SetID(id BallotID) {
	b.ballotID = id
}

// ID returns the BallotID.
func (b *Ballot) ID() BallotID {
	return b.ballotID
}

// SetSmesherID from stored data.
func (b *Ballot) SetSmesherID(id NodeID) {
	b.smesherID = id
}

// SmesherID returns the smesher's Edwards public key.
func (b *Ballot) SmesherID() NodeID {
	return b.smesherID
}

// SetMalicious sets ballot as malicious.
func (b *Ballot) SetMalicious() {
	b.malicious = true
}

// IsMalicious returns true if ballot is malicious.
func (b *Ballot) IsMalicious() bool {
	return b.malicious
}

// MarshalLogObject implements logging encoder for Ballot.
func (b *Ballot) MarshalLogObject(encoder log.ObjectEncoder) error {
	var (
		activeSetSize = 0
		beacon        Beacon
	)

	if b.EpochData != nil {
		activeSetSize = len(b.ActiveSet)
		beacon = b.EpochData.Beacon
	}

	encoder.AddString("ballot_id", b.ID().String())
	encoder.AddUint32("layer_id", b.Layer.Value)
	encoder.AddUint32("epoch_id", uint32(b.Layer.GetEpoch()))
	encoder.AddString("smesher", b.SmesherID().String())
	encoder.AddString("opinion hash", b.OpinionHash.String())
	encoder.AddString("base_ballot", b.Votes.Base.String())
	encoder.AddInt("support", len(b.Votes.Support))
	encoder.AddInt("against", len(b.Votes.Against))
	encoder.AddInt("abstain", len(b.Votes.Abstain))
	encoder.AddString("atx_id", b.AtxID.String())
	encoder.AddString("ref_ballot", b.RefBallot.String())
	encoder.AddInt("active_set_size", activeSetSize)
	encoder.AddString("beacon", beacon.ShortString())
	encoder.AddObject("votes", &b.Votes)
	return nil
}

// ToBallotIDs turns a list of Ballot into a list of BallotID.
func ToBallotIDs(ballots []*Ballot) []BallotID {
	ids := make([]BallotID, 0, len(ballots))
	for _, b := range ballots {
		ids = append(ids, b.ID())
	}
	return ids
}

// String returns a short prefix of the hex representation of the ID.
func (id BallotID) String() string {
	return id.AsHash32().ShortString()
}

// Bytes returns the BallotID as a byte slice.
func (id BallotID) Bytes() []byte {
	return id.AsHash32().Bytes()
}

// AsHash32 returns a Hash32 whose first 20 bytes are the bytes of this BallotID, it is right-padded with zeros.
func (id BallotID) AsHash32() Hash32 {
	return Hash20(id).ToHash32()
}

// Field returns a log field. Implements the LoggableField interface.
func (id BallotID) Field() log.Field {
	return log.String("ballot_id", id.String())
}

// Compare returns true if other (the given BallotID) is less than this BallotID, by lexicographic comparison.
func (id BallotID) Compare(other BallotID) bool {
	return bytes.Compare(id.Bytes(), other.Bytes()) < 0
}

// BallotIDsToHashes turns a list of BallotID into their Hash32 representation.
func BallotIDsToHashes(ids []BallotID) []Hash32 {
	hashes := make([]Hash32, 0, len(ids))
	for _, id := range ids {
		hashes = append(hashes, id.AsHash32())
	}
	return hashes
}

// NewExistingBallot creates ballot from stored data.
func NewExistingBallot(id BallotID, sig EdSignature, nodeId NodeID, meta BallotMetadata) Ballot {
	return Ballot{
		ballotID:       id,
		Signature:      sig,
		smesherID:      nodeId,
		BallotMetadata: meta,
	}
}
