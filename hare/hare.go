package hare

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/spacemeshos/go-spacemesh/codec"
	"github.com/spacemeshos/go-spacemesh/common/types"
	"github.com/spacemeshos/go-spacemesh/datastore"
	"github.com/spacemeshos/go-spacemesh/hare/config"
	"github.com/spacemeshos/go-spacemesh/log"
	"github.com/spacemeshos/go-spacemesh/malfeasance"
	"github.com/spacemeshos/go-spacemesh/miner"
	"github.com/spacemeshos/go-spacemesh/p2p/pubsub"
	"github.com/spacemeshos/go-spacemesh/signing"
	"github.com/spacemeshos/go-spacemesh/sql"
	"github.com/spacemeshos/go-spacemesh/sql/ballots"
	"github.com/spacemeshos/go-spacemesh/sql/identities"
	"github.com/spacemeshos/go-spacemesh/sql/proposals"
	"github.com/spacemeshos/go-spacemesh/system"
)

type consensusFactory func(
	context.Context,
	config.Config,
	types.LayerID,
	*Set,
	Rolacle,
	*EligibilityTracker,
	*signing.EdSigner,
	pubsub.Publisher,
	communication,
	RoundClock,
) Consensus

// Consensus represents an item that acts like a consensus process.
type Consensus interface {
	ID() types.LayerID
	Start()
	Stop()
}

// RoundClock is a timer interface.
type RoundClock interface {
	AwaitWakeup() <-chan struct{}
	// RoundEnd returns the time at which round ends, passing round-1 will
	// return the time at which round starts.
	RoundEnd(round uint32) time.Time
	AwaitEndOfRound(round uint32) <-chan struct{}
}

// LayerClock provides a timer for the start of a given layer, as well as the current layer and allows converting a
// layer number to a clock time.
type LayerClock interface {
	LayerToTime(types.LayerID) time.Time
	AwaitLayer(types.LayerID) <-chan struct{}
	CurrentLayer() types.LayerID
}

// LayerOutput is the output of each hare consensus process.
type LayerOutput struct {
	Ctx       context.Context
	Layer     types.LayerID
	Proposals []types.ProposalID
}

type defaultMesh struct {
	*datastore.CachedDB
}

func (m defaultMesh) Proposals(lid types.LayerID) ([]*types.Proposal, error) {
	return proposals.GetByLayer(m, lid)
}

func (m defaultMesh) Ballot(bid types.BallotID) (*types.Ballot, error) {
	return ballots.Get(m, bid)
}

func (m defaultMesh) Cache() *datastore.CachedDB {
	return m.CachedDB
}

// Opt for configuring beacon protocol.
type Opt func(*Hare)

func withMesh(m mesh) Opt {
	return func(h *Hare) {
		h.msh = m
	}
}

// Hare is the orchestrator that starts new consensus processes and collects their output.
type Hare struct {
	log.Log
	msh        mesh
	weakCoin   weakCoin
	config     config.Config
	publisher  pubsub.Publisher
	layerClock LayerClock
	broker     *Broker
	sign       *signing.EdSigner
	blockGenCh chan LayerOutput

	// channel to receive MalfeasanceGossip generated by the broker and the consensus processes.
	mchMalfeasance chan *types.MalfeasanceGossip

	beacons       system.BeaconGetter
	rolacle       Rolacle
	patrol        layerPatrol
	newRoundClock func(LayerID types.LayerID) RoundClock

	networkDelta time.Duration

	outputChan chan report
	wcChan     chan wcReport
	mu         sync.Mutex
	lastLayer  types.LayerID
	outputs    map[types.LayerID][]types.ProposalID
	cps        map[types.LayerID]Consensus

	factory consensusFactory

	nodeID      types.NodeID
	sigVerifier malfeasance.SigVerifier

	ctx    context.Context
	cancel context.CancelFunc
	eg     errgroup.Group
}

// New returns a new Hare struct.
func New(
	cdb *datastore.CachedDB,
	conf config.Config,
	publisher pubsub.PublishSubsciber,
	sign *signing.EdSigner,
	edVerifier *signing.EdVerifier,
	nid types.NodeID,
	ch chan LayerOutput,
	syncState system.SyncStateProvider,
	beacons system.BeaconGetter,
	rolacle Rolacle,
	patrol layerPatrol,
	stateQ stateQuerier,
	layerClock LayerClock,
	weakCoin weakCoin,
	logger log.Log,
	opts ...Opt,
) *Hare {
	h := new(Hare)

	h.Log = logger
	h.config = conf
	h.publisher = publisher
	h.layerClock = layerClock
	h.newRoundClock = func(layerID types.LayerID) RoundClock {
		layerTime := layerClock.LayerToTime(layerID)
		wakeupDelta := conf.WakeupDelta
		roundDuration := h.config.RoundDuration
		h.With().Debug("creating hare round clock", layerID,
			log.String("layer_time", layerTime.String()),
			log.Duration("wakeup_delta", wakeupDelta),
			log.Duration("round_duration", roundDuration),
		)
		return NewSimpleRoundClock(layerTime, wakeupDelta, roundDuration)
	}

	ev := newEligibilityValidator(rolacle, conf.N, conf.ExpectedLeaders, logger)
	h.mchMalfeasance = make(chan *types.MalfeasanceGossip, conf.N)
	h.sign = sign
	h.blockGenCh = ch

	h.beacons = beacons
	h.rolacle = rolacle
	h.patrol = patrol
	h.weakCoin = weakCoin

	h.networkDelta = conf.WakeupDelta
	h.outputChan = make(chan report, h.config.Hdist)
	h.wcChan = make(chan wcReport, h.config.Hdist)
	h.outputs = make(map[types.LayerID][]types.ProposalID, h.config.Hdist) // we keep results about LayerBuffer past layers
	h.cps = make(map[types.LayerID]Consensus, h.config.LimitConcurrent)
	h.factory = func(ctx context.Context, conf config.Config, instanceId types.LayerID, s *Set, oracle Rolacle, et *EligibilityTracker, signing *signing.EdSigner, p2p pubsub.Publisher, comm communication, clock RoundClock) Consensus {
		return newConsensusProcess(ctx, conf, instanceId, s, oracle, stateQ, signing, edVerifier, et, nid, p2p, comm, ev, clock, logger)
	}

	h.nodeID = nid
	h.sigVerifier = edVerifier
	h.ctx, h.cancel = context.WithCancel(context.Background())

	for _, opt := range opts {
		opt(h)
	}

	if h.msh == nil {
		h.msh = defaultMesh{CachedDB: cdb}
	}
	h.broker = newBroker(h.config, h.msh, edVerifier, ev, stateQ, syncState, publisher, conf.LimitConcurrent, logger)

	return h
}

// GetHareMsgHandler returns the gossip handler for hare protocol message.
func (h *Hare) GetHareMsgHandler() pubsub.GossipHandler {
	return h.broker.HandleMessage
}

func (h *Hare) HandleEligibility(ctx context.Context, emsg *types.HareEligibilityGossip) {
	h.broker.HandleEligibility(ctx, emsg)
}

func (h *Hare) getLastLayer() types.LayerID {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastLayer
}

func (h *Hare) setLastLayer(layerID types.LayerID) {
	if layerID == 0 {
		// layers starts from 0. nothing to do here.
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if layerID.After(h.lastLayer) {
		h.lastLayer = layerID
	} else {
		h.With().Error("received out of order layer tick", log.FieldNamed("last_layer", h.lastLayer))
	}
}

// checks if the provided id is too late/old to be requested.
func (h *Hare) outOfBufferRange(id types.LayerID) bool {
	last := h.getLastLayer()
	if !last.After(types.LayerID(h.config.Hdist)) {
		return false
	}
	if id.Before(last.Sub(h.config.Hdist)) { // bufferSize>=0
		return true
	}
	return false
}

func (h *Hare) oldestResultInBuffer() types.LayerID {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.oldestResultInBufferLocked()
}

func (h *Hare) oldestResultInBufferLocked() types.LayerID {
	// buffer is usually quite small so its cheap to iterate.
	// TODO: if it gets bigger change `outputs` to array.
	lyr := types.LayerID(math.MaxUint32)
	for k := range h.outputs {
		if k.Before(lyr) {
			lyr = k
		}
	}
	return lyr
}

// ErrTooLate means that the consensus was terminated too late.
var ErrTooLate = errors.New("consensus process finished too late")

// records the provided output.
func (h *Hare) collectOutput(ctx context.Context, output report) error {
	layerID := output.id

	var pids []types.ProposalID
	if output.completed {
		consensusOkCnt.Inc()
		h.WithContext(ctx).With().Info("hare terminated with success", layerID, log.Int("num_proposals", output.set.Size()))
		set := output.set
		postNumProposals.Add(float64(set.Size()))
		pids = set.ToSlice()
		select {
		case h.blockGenCh <- LayerOutput{
			Ctx:       ctx,
			Layer:     layerID,
			Proposals: pids,
		}:
		case <-ctx.Done():
		}
	} else {
		consensusFailCnt.Inc()
		h.WithContext(ctx).With().Warning("hare terminated with failure", layerID)
	}

	if h.outOfBufferRange(layerID) {
		return ErrTooLate
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if uint32(len(h.outputs)) >= h.config.Hdist {
		delete(h.outputs, h.oldestResultInBufferLocked())
	}
	h.outputs[layerID] = pids
	return nil
}

func (h *Hare) isClosed() bool {
	select {
	case <-h.ctx.Done():
		return true
	default:
		return false
	}
}

// the logic that happens when a new layer arrives.
// this function triggers the start of new consensus processes.
func (h *Hare) onTick(ctx context.Context, lid types.LayerID) (bool, error) {
	if h.isClosed() {
		h.With().Debug("hare exiting", log.Context(ctx), lid)
		return false, nil
	}

	h.setLastLayer(lid)

	if lid <= types.GetEffectiveGenesis() {
		h.With().Debug("not starting hare: genesis", log.Context(ctx), lid)
		return false, nil
	}

	// call to start the calculation of active set size beforehand
	h.eg.Go(func() error {
		if !h.broker.Synced(ctx, lid) {
			return nil
		}
		// this is called only for its side effects, but at least print the error if it returns one
		if isActive, err := h.rolacle.IsIdentityActiveOnConsensusView(ctx, h.nodeID, lid); err != nil {
			h.With().Warning("error checking if identity is active",
				log.Context(ctx),
				lid,
				log.Bool("isActive", isActive),
				log.Err(err),
			)
		}
		return nil
	})

	h.With().Debug("hare got tick, sleeping",
		log.Context(ctx),
		lid,
		log.String("delta", fmt.Sprint(h.networkDelta)),
	)

	clock := h.newRoundClock(lid)
	select {
	case <-clock.AwaitWakeup():
		break // keep going
	case <-h.ctx.Done():
		return false, errors.New("closed while waiting for hare delta")
	}

	if !h.broker.Synced(ctx, lid) {
		// if not currently synced don't start consensus process
		h.With().Info("not starting hare: node not synced at this layer",
			log.Context(ctx),
			lid,
		)
		return false, nil
	}

	var err error
	beacon, err := h.beacons.GetBeacon(lid.GetEpoch())
	if err != nil {
		h.With().Info("not starting hare: beacon not retrieved",
			log.Context(ctx),
			lid,
		)
		return false, nil
	}

	ch, et, err := h.broker.Register(ctx, lid)
	if err != nil {
		return false, fmt.Errorf("broker register: %w", err)
	}
	comm := communication{
		inbox:  ch,
		mchOut: h.mchMalfeasance,
		report: h.outputChan,
		wc:     h.wcChan,
	}
	props := goodProposals(ctx, h.Log, h.msh, h.nodeID, lid, beacon, h.layerClock.LayerToTime(lid.GetEpoch().FirstLayer()), h.config.WakeupDelta)
	preNumProposals.Add(float64(len(props)))
	set := NewSet(props)
	cp := h.factory(ctx, h.config, lid, set, h.rolacle, et, h.sign, h.publisher, comm, clock)

	h.With().Debug("starting hare",
		log.Context(ctx),
		lid,
		log.Int("num proposals", len(props)),
	)
	cp.Start()
	h.addCP(ctx, cp)
	h.patrol.SetHareInCharge(lid)
	return true, nil
}

func (h *Hare) addCP(ctx context.Context, cp Consensus) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cps[cp.ID()] = cp
	h.With().Debug("number of consensus processes (after register)",
		log.Context(ctx),
		log.Int("count", len(h.cps)),
	)
	processesGauge.Set(float64(len(h.cps)))
}

func (h *Hare) getCP(lid types.LayerID) Consensus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cps[lid]
}

func (h *Hare) removeCP(ctx context.Context, lid types.LayerID) {
	cp := h.getCP(lid)
	if cp == nil {
		h.With().Error("failed to find consensus process", log.Context(ctx), lid)
		return
	}
	// do not hold lock while waiting for consensus process to terminate
	cp.Stop()

	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.cps, cp.ID())
	h.With().Debug("number of consensus processes (after deregister)",
		log.Context(ctx),
		lid,
		log.Int("count", len(h.cps)))
	processesGauge.Set(float64(len(h.cps)))
}

// goodProposals finds the "good proposals" for the specified layer. a proposal is good if
// - it has the same beacon value as the node's beacon value.
// - its miner is not malicious
// - its active set contains only grade 1 or grade 2 atxs
// see (https://community.spacemesh.io/t/grading-atxs-for-the-active-set/335#proposal-voting-4)
// any error encountered will be ignored and an empty set is returned.
func goodProposals(
	ctx context.Context,
	logger log.Log,
	msh mesh,
	nodeID types.NodeID,
	lid types.LayerID,
	epochBeacon types.Beacon,
	epochStart time.Time,
	networkDelay time.Duration,
) []types.ProposalID {
	props, err := msh.Proposals(lid)
	if err != nil {
		if errors.Is(err, sql.ErrNotFound) {
			logger.With().Warning("no proposals found for hare, using empty set", log.Context(ctx), lid, log.Err(err))
		} else {
			logger.With().Error("failed to get proposals for hare", log.Context(ctx), lid, log.Err(err))
		}
		return []types.ProposalID{}
	}

	var (
		beacon        types.Beacon
		activeSet     []types.ATXID
		result        []types.ProposalID
		ownHdr        *types.ActivationTxHeader
		ownTickHeight = uint64(math.MaxUint64)
	)
	// a non-smesher will not filter out any proposals, as it doesn't have voting power
	// and only observes the consensus process.
	ownHdr, err = msh.GetEpochAtx(lid.GetEpoch()-1, nodeID)
	if err != nil && !errors.Is(err, sql.ErrNotFound) {
		logger.With().Error("failed to get own atx", log.Context(ctx), lid, log.Err(err))
		return []types.ProposalID{}
	}
	if ownHdr != nil {
		ownTickHeight = ownHdr.TickHeight()
	}
	atxs := map[types.ATXID]int{}
	for _, p := range props {
		atxs[p.AtxID]++
	}
	for _, p := range props {
		if p.IsMalicious() {
			logger.With().Warning("not voting on proposal from malicious identity",
				log.Stringer("id", p.ID()),
			)
			continue
		}
		if n := atxs[p.AtxID]; n > 1 {
			logger.With().Warning("proposal with same atx added several times in the recorded set",
				log.Int("n", n),
				log.Stringer("id", p.ID()),
				log.Stringer("atxid", p.AtxID),
			)
			continue
		}
		if ownHdr != nil {
			hdr, err := msh.GetAtxHeader(p.AtxID)
			if err != nil {
				logger.With().Error("failed to get atx", log.Context(ctx), lid, p.AtxID, log.Err(err))
				return []types.ProposalID{}
			}
			if hdr.BaseTickHeight >= ownTickHeight {
				// does not vote for future proposal
				logger.With().Warning("proposal base tick height too high. skipping",
					log.Context(ctx),
					lid,
					log.Uint64("proposal_height", hdr.BaseTickHeight),
					log.Uint64("own_height", ownTickHeight),
				)
				continue
			}
		}
		if p.EpochData != nil {
			beacon = p.EpochData.Beacon
			activeSet = p.ActiveSet
		} else if p.RefBallot == types.EmptyBallotID {
			logger.With().Error("proposal missing ref ballot",
				log.Context(ctx),
				lid,
				p.ID(),
			)
			return []types.ProposalID{}
		} else if refBallot, err := msh.Ballot(p.RefBallot); err != nil {
			logger.With().Error("failed to get ref ballot",
				log.Context(ctx),
				lid,
				p.ID(),
				p.RefBallot,
				log.Err(err))
			return []types.ProposalID{}
		} else if refBallot.EpochData == nil {
			logger.With().Error("ref ballot missing epoch data",
				log.Context(ctx),
				p.ID(),
				lid,
				refBallot.ID(),
			)
			return []types.ProposalID{}
		} else {
			beacon = refBallot.EpochData.Beacon
			activeSet = refBallot.ActiveSet
		}

		if len(activeSet) == 0 {
			logger.With().Error("proposal missing active set",
				log.Context(ctx),
				p.ID(),
				lid,
			)
			return []types.ProposalID{}
		}
		if evil, err := gradeActiveSet(activeSet, msh, epochStart, networkDelay); err != nil {
			logger.With().Error("failed to grade active set",
				log.Context(ctx),
				lid,
				p.ID(),
				log.Err(err),
			)
			return []types.ProposalID{}
		} else if evil != types.EmptyATXID {
			logger.With().Warning("proposal has grade 0 active set",
				log.Context(ctx),
				lid,
				p.ID(),
				log.Stringer("evil atx", evil),
			)
			continue
		}

		if beacon == epochBeacon {
			result = append(result, p.ID())
		} else {
			logger.With().Warning("proposal has different beacon value",
				log.Context(ctx),
				lid,
				p.ID(),
				log.String("proposal_beacon", beacon.ShortString()),
				log.String("epoch_beacon", epochBeacon.ShortString()))
		}
	}
	return result
}

func gradeActiveSet(activeSet []types.ATXID, msh mesh, epochStart time.Time, networkDelay time.Duration) (types.ATXID, error) {
	for _, id := range activeSet {
		hdr, err := msh.GetAtxHeader(id)
		if err != nil {
			return types.EmptyATXID, fmt.Errorf("get header %v: %s", id, err)
		}
		grade, err := miner.GradeAtx(msh, hdr.NodeID, hdr.Received, epochStart, networkDelay)
		if err != nil {
			return types.EmptyATXID, fmt.Errorf("grade %v: %w", id, err)
		}
		if grade == miner.Evil {
			return id, nil
		}
	}
	return types.EmptyATXID, nil
}

var (
	errTooOld   = errors.New("layer has already been evacuated from buffer")
	errNoResult = errors.New("no result for the requested layer")
)

func (h *Hare) getResult(lid types.LayerID) ([]types.ProposalID, error) {
	if h.outOfBufferRange(lid) {
		return nil, errTooOld
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	props, ok := h.outputs[lid]
	if !ok {
		return nil, errNoResult
	}

	return props, nil
}

// listens to outputs arriving from consensus processes.
func (h *Hare) outputCollectionLoop(ctx context.Context) {
	h.WithContext(ctx).With().Info("starting collection loop")
	for {
		select {
		case wc := <-h.wcChan:
			h.With().Debug("recording weak coin result for layer",
				log.Context(ctx),
				wc.id,
				log.Bool("weak_coin", wc.coinflip))
			if err := h.weakCoin.Set(wc.id, wc.coinflip); err != nil {
				h.With().Error("failed to set weak coin for layer",
					log.Context(ctx),
					wc.id,
					log.Err(err),
				)
			}
		case out := <-h.outputChan:
			layerID := out.id
			ctx := log.WithNewSessionID(ctx)
			if err := h.collectOutput(ctx, out); err != nil {
				h.With().Warning("error collecting output from hare",
					log.Context(ctx),
					layerID,
					log.Err(err),
				)
			}
			h.broker.Unregister(ctx, out.id)
			h.removeCP(ctx, out.id)
		case <-h.ctx.Done():
			return
		}
	}
}

// listens to new layers.
func (h *Hare) tickLoop(ctx context.Context) {
	for layer := h.layerClock.CurrentLayer(); ; layer = layer.Add(1) {
		ctx := log.WithNewSessionID(ctx)
		select {
		case <-h.layerClock.AwaitLayer(layer):
			if time.Since(h.layerClock.LayerToTime(layer)) > h.config.WakeupDelta {
				h.WithContext(ctx).With().Warning("missed hare window, skipping layer", layer)
				continue
			}
			_, err := h.onTick(ctx, layer)
			if err != nil && !errors.Is(err, context.Canceled) {
				h.With().Warning("hare failed", log.Context(ctx), layer, log.Err(err))
			}
			h.broker.CleanOldLayers(layer)
		case <-h.ctx.Done():
			return
		}
	}
}

// process two types of messages:
//   - HareEligibilityGossip received from MalfeasanceProof gossip handler:
//     relay to the running consensus instance if running.
//   - MalfeasanceProofGossip generated during the consensus processes:
//     save it to database and broadcast to network.
func (h *Hare) malfeasanceLoop(ctx context.Context) {
	h.WithContext(ctx).With().Info("starting malfeasance loop")
	for {
		select {
		case gossip := <-h.mchMalfeasance:
			if gossip.Eligibility == nil {
				h.WithContext(ctx).Panic("missing hare eligibility")
			}
			encoded, err := codec.Encode(&gossip.MalfeasanceProof)
			if err != nil {
				h.WithContext(ctx).With().Panic("failed to encode MalfeasanceProof", log.Err(err))
			}
			if err := identities.SetMalicious(h.msh.Cache(), gossip.Eligibility.NodeID, encoded, time.Now()); err != nil {
				h.With().Error("failed to save MalfeasanceProof",
					log.Context(ctx),
					gossip.Eligibility.NodeID,
					log.Err(err),
				)
				continue
			}
			h.msh.Cache().CacheMalfeasanceProof(gossip.Eligibility.NodeID, &gossip.MalfeasanceProof)
			gossipBytes, err := codec.Encode(gossip)
			if err != nil {
				h.With().Fatal("failed to encode MalfeasanceGossip",
					log.Context(ctx),
					gossip.Eligibility.NodeID,
					log.Err(err),
				)
			}
			if err = h.publisher.Publish(ctx, pubsub.MalfeasanceProof, gossipBytes); err != nil {
				h.With().Error("failed to broadcast MalfeasanceProof",
					log.Context(ctx),
					gossip.Eligibility.NodeID,
					log.Err(err),
				)
			}
		case <-ctx.Done():
			return
		case <-h.ctx.Done():
			return
		}
	}
}

// Start starts listening for layers and outputs.
func (h *Hare) Start(ctx context.Context) error {
	{
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.cancel != nil {
			h.cancel()
		}
		h.ctx, h.cancel = context.WithCancel(ctx)
		ctx = h.ctx
	}
	h.WithContext(ctx).With().Info("starting protocol", log.String("protocol", pubsub.HareProtocol))

	// Create separate contexts for each subprocess. This allows us to better track the flow of messages.
	ctxBroker := log.WithNewSessionID(ctx, log.String("protocol", pubsub.HareProtocol+"_broker"))
	ctxTickLoop := log.WithNewSessionID(ctx, log.String("protocol", pubsub.HareProtocol+"_tickloop"))
	ctxOutputLoop := log.WithNewSessionID(ctx, log.String("protocol", pubsub.HareProtocol+"_outputloop"))
	ctxMalfLoop := log.WithNewSessionID(ctx, log.String("protocol", pubsub.HareProtocol+"_malfloop"))

	h.broker.Start(ctxBroker)

	h.eg.Go(func() error {
		h.tickLoop(ctxTickLoop)
		return nil
	})
	h.eg.Go(func() error {
		h.outputCollectionLoop(ctxOutputLoop)
		return nil
	})
	h.eg.Go(func() error {
		h.malfeasanceLoop(ctxMalfLoop)
		return nil
	})

	return nil
}

// Close sends a termination signal to hare goroutines and waits for their termination.
func (h *Hare) Close() {
	h.cancel()
	_ = h.eg.Wait()
}

func reportEquivocation(
	ctx context.Context,
	pubKey types.NodeID,
	old, new *types.HareProofMsg,
	eligibility *types.HareEligibility,
	mch chan<- *types.MalfeasanceGossip,
) error {
	gossip := &types.MalfeasanceGossip{
		MalfeasanceProof: types.MalfeasanceProof{
			Layer: old.InnerMsg.Layer,
			Proof: types.Proof{
				Type: types.HareEquivocation,
				Data: &types.HareProof{
					Messages: [2]types.HareProofMsg{*old, *new},
				},
			},
		},
		Eligibility: &types.HareEligibilityGossip{
			Layer:       old.InnerMsg.Layer,
			Round:       old.InnerMsg.Round,
			NodeID:      pubKey,
			Eligibility: *eligibility,
		},
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case mch <- gossip:
	}
	return nil
}
