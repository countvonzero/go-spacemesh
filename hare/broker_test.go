package hare

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spacemeshos/go-spacemesh/codec"
	"github.com/spacemeshos/go-spacemesh/common/types"
	"github.com/spacemeshos/go-spacemesh/log/logtest"
	"github.com/spacemeshos/go-spacemesh/p2p/pubsub"
	"github.com/spacemeshos/go-spacemesh/signing"
)

var (
	instanceID0 = types.NewLayerID(0)
	instanceID1 = types.NewLayerID(1)
	instanceID2 = types.NewLayerID(2)
	instanceID3 = types.NewLayerID(3)
	instanceID4 = types.NewLayerID(4)
	instanceID5 = types.NewLayerID(5)
	instanceID6 = types.NewLayerID(6)
	instanceID7 = types.NewLayerID(7)
)

const reqID = "abracadabra"

func trueFunc(context.Context) bool {
	return true
}

func falseFunc(context.Context) bool {
	return false
}

func mustEncode(tb testing.TB, value interface{}) []byte {
	tb.Helper()
	buf, err := codec.Encode(value)
	require.NoError(tb, err)
	return buf
}

type mockClient struct {
	id types.LayerID
}

type MockStateQuerier struct {
	res bool
	err error
}

func NewMockStateQuerier() MockStateQuerier {
	return MockStateQuerier{true, nil}
}

func (msq MockStateQuerier) IsIdentityActiveOnConsensusView(ctx context.Context, edID string, layer types.LayerID) (bool, error) {
	return msq.res, msq.err
}

func createMessage(tb testing.TB, instanceID types.LayerID) []byte {
	tb.Helper()

	sr := signing.NewEdSigner()
	b := newMessageBuilder()
	msg := b.SetPubKey(sr.PublicKey()).SetInstanceID(instanceID).Sign(sr).Build()
	return mustEncode(tb, msg.Message)
}

func TestBroker_Start(t *testing.T) {
	broker := buildBroker(t, t.Name())

	err := broker.Start(context.TODO())
	assert.Nil(t, err)

	err = broker.Start(context.TODO())
	assert.NotNil(t, err)
	assert.Equal(t, "instance already started", err.Error())
}

// test that a InnerMsg to a specific set ID is delivered by the broker.
func TestBroker_Received(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())

	inbox, err := broker.Register(context.TODO(), instanceID1)
	assert.Nil(t, err)

	serMsg := createMessage(t, instanceID1)
	broker.HandleMessage(context.TODO(), "", serMsg)
	waitForMessages(t, inbox, instanceID1, 1)
}

// test that self-generated (outbound) messages are handled before incoming messages.
func TestBroker_Priority(t *testing.T) {
	broker := buildBroker(t, t.Name())

	// this allows us to pause and release broker processing of incoming messages
	wg := sync.WaitGroup{}
	wg.Add(1)
	wg2 := sync.WaitGroup{}
	wg2.Add(1)
	once := sync.Once{}
	broker.eValidator = &mockEligibilityValidator{validationFn: func(context.Context, *Msg) bool {
		// tell the sender that we've got one message
		once.Do(wg2.Done)
		// wait until all the messages are queued
		wg.Wait()
		return true
	}}
	require.NoError(t, broker.Start(context.TODO()))

	// take control of the broker inbox so we can feed it messages in a deterministic order
	// make the channel blocking (no buffer) so we can be sure the messages have been processed
	outbox, err := broker.Register(context.TODO(), instanceID1)
	assert.Nil(t, err)

	createMessageWithRoleProof := func(roleProof []byte) []byte {
		sr := signing.NewEdSigner()
		b := newMessageBuilder()
		msg := b.SetPubKey(sr.PublicKey()).SetInstanceID(instanceID1).SetRoleProof(roleProof).Sign(sr).Build()
		return mustEncode(t, msg.Message)
	}
	roleProofInbound := []byte{1, 2, 3}
	roleProofOutbound := []byte{3, 2, 1}
	serMsgInbound := createMessageWithRoleProof(roleProofInbound)
	serMsgOutbound := createMessageWithRoleProof(roleProofOutbound)

	// first, broadcast a bunch of simulated inbound messages
	for i := 0; i < 10; i++ {
		// channel send is blocking, so we're sure the messages have been processed
		broker.queueMessage(context.TODO(), "not-self", serMsgInbound)
	}

	// make sure the listener has gotten at least one message
	wg2.Wait()

	// now broadcast one outbound message
	broker.queueMessage(context.TODO(), broker.pid, serMsgOutbound)

	// all messages are queued, release the waiting listener (hare event loop)
	wg.Done()

	// we expect the outbound message to be prioritized
	tm := time.NewTimer(3 * time.Minute)
	for i := 0; i < 11; i++ {
		select {
		case x := <-outbox:
			switch i {
			case 0:
				// first message (already queued) should be inbound
				assert.Equal(t, roleProofInbound, x.InnerMsg.RoleProof, "expected inbound msg %d", i)
			case 1:
				// second message should be outbound
				assert.Equal(t, roleProofOutbound, x.InnerMsg.RoleProof, "expected outbound msg %d", i)
			default:
				// all subsequent messages should be inbound
				assert.Equal(t, roleProofInbound, x.InnerMsg.RoleProof, "expected inbound msg %d", i)
			}
		case <-tm.C:
			assert.Fail(t, "timed out waiting for message", "msg %d", i)
			return
		}
	}
	assert.Len(t, outbox, 0, "expected broker queue to be empty")

	// Test shutdown flow

	// Listener to make sure internal queue channel is closed
	wg3 := sync.WaitGroup{}
	wg3.Add(1)
	res := make(chan bool)
	go func() {
		timeout := time.NewTimer(time.Second)
		wg3.Done()
		select {
		case <-timeout.C:
			assert.Fail(t, "timed out waiting for channel close")
			res <- false
		case _, ok := <-broker.queueChannel:
			assert.False(t, ok, "expected channel close")
			res <- !ok
		}
	}()

	// Make sure the listener is listening
	wg3.Wait()
	broker.Close()
	_, err = broker.queue.Read()
	assert.Error(t, err, "expected broker priority queue to be closed")
	assert.True(t, <-res)
}

// test that after registering the maximum number of protocols,
// the earliest one gets unregistered in favor of the newest one.
func TestBroker_MaxConcurrentProcesses(t *testing.T) {
	broker := buildBrokerLimit4(t, t.Name())
	broker.Start(context.TODO())

	broker.Register(context.TODO(), instanceID1)
	broker.Register(context.TODO(), instanceID2)
	broker.Register(context.TODO(), instanceID3)
	broker.Register(context.TODO(), instanceID4)
	assert.Equal(t, 4, len(broker.outbox))

	// this statement should cause inbox1 to be unregistered
	inbox5, _ := broker.Register(context.TODO(), instanceID5)
	assert.Equal(t, 4, len(broker.outbox))

	serMsg := createMessage(t, instanceID5)
	broker.HandleMessage(context.TODO(), "", serMsg)
	waitForMessages(t, inbox5, instanceID5, 1)
	assert.Nil(t, broker.outbox[instanceID1.Uint32()])

	inbox6, _ := broker.Register(context.TODO(), instanceID6)
	assert.Equal(t, 4, len(broker.outbox))
	assert.Nil(t, broker.outbox[instanceID2.Uint32()])

	serMsg = createMessage(t, instanceID6)
	broker.HandleMessage(context.TODO(), "", serMsg)
	waitForMessages(t, inbox6, instanceID6, 1)
}

// test that aborting the broker aborts.
func TestBroker_Abort(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())

	timer := time.NewTimer(3 * time.Second)

	go broker.Close()

	select {
	case <-broker.CloseChannel():
		assert.True(t, true)
	case <-timer.C:
		assert.Fail(t, "timeout")
	}
}

func sendMessages(t *testing.T, instanceID types.LayerID, broker *Broker, count int) {
	for i := 0; i < count; i++ {
		broker.HandleMessage(context.TODO(), "", createMessage(t, instanceID))
	}
}

func waitForMessages(t *testing.T, inbox chan *Msg, instanceID types.LayerID, msgCount int) {
	i := 0
	for {
		tm := time.NewTimer(3 * time.Second)
		for {
			select {
			case x := <-inbox:
				assert.True(t, x.InnerMsg.InstanceID == instanceID)
				i++
				if i >= msgCount {
					return
				}
			case <-tm.C:
				t.Errorf("Timed out waiting for msg %v", i)
				t.Fail()
				return
			}
		}
	}
}

// test flow for multiple set ObjectID.
func TestBroker_MultipleInstanceIds(t *testing.T) {
	const msgCount = 1

	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())

	inbox1, _ := broker.Register(context.TODO(), instanceID1)
	inbox2, _ := broker.Register(context.TODO(), instanceID2)
	inbox3, _ := broker.Register(context.TODO(), instanceID3)

	go sendMessages(t, instanceID1, broker, msgCount)
	go sendMessages(t, instanceID2, broker, msgCount)
	go sendMessages(t, instanceID3, broker, msgCount)

	go waitForMessages(t, inbox1, instanceID1, msgCount)
	go waitForMessages(t, inbox2, instanceID2, msgCount)
	waitForMessages(t, inbox3, instanceID3, msgCount)

	assert.True(t, true)
}

func TestBroker_RegisterUnregister(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())
	broker.Register(context.TODO(), instanceID1)
	assert.Equal(t, 1, len(broker.outbox))
	broker.Unregister(context.TODO(), instanceID1)
	assert.Nil(t, broker.outbox[instanceID1.Uint32()])
}

func newMockGossipMsg(msg *Message) *Msg {
	return &Msg{msg, nil, ""}
}

func TestBroker_Send(t *testing.T) {
	ctx := context.TODO()
	broker := buildBroker(t, t.Name())
	mev := &mockEligibilityValidator{valid: false}
	broker.eValidator = mev
	broker.Start(ctx)

	require.Equal(t, pubsub.ValidationIgnore, broker.HandleMessage(ctx, "", nil))

	msg := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil).Message
	msg.InnerMsg.InstanceID = types.NewLayerID(2)
	require.Equal(t, pubsub.ValidationIgnore, broker.HandleMessage(ctx, "", mustEncode(t, msg)))

	msg.InnerMsg.InstanceID = types.NewLayerID(1)
	require.Equal(t, pubsub.ValidationIgnore, broker.HandleMessage(ctx, "", mustEncode(t, msg)))
	// nothing happens since this is an invalid InnerMsg

	mev.valid = true
	require.Equal(t, pubsub.ValidationAccept, broker.HandleMessage(ctx, "", mustEncode(t, msg)))
}

func TestBroker_Register(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())
	msg := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil)
	broker.pending[instanceID1.Uint32()] = []*Msg{msg, msg}
	broker.Register(context.TODO(), instanceID1)
	assert.Equal(t, 2, len(broker.outbox[instanceID1.Uint32()]))
	assert.Equal(t, 0, len(broker.pending[instanceID1.Uint32()]))
}

func TestBroker_Register2(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())
	broker.Register(context.TODO(), instanceID1)
	m := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil).Message
	m.InnerMsg.InstanceID = instanceID1

	msg := newMockGossipMsg(m).Message
	require.Equal(t, pubsub.ValidationAccept, broker.HandleMessage(context.TODO(), "", mustEncode(t, msg)))

	m.InnerMsg.InstanceID = instanceID2
	msg = newMockGossipMsg(m).Message
	require.Equal(t, pubsub.ValidationAccept, broker.HandleMessage(context.TODO(), "", mustEncode(t, msg)))
}

func TestBroker_Register3(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())

	m := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil).Message
	m.InnerMsg.InstanceID = instanceID1

	broker.HandleMessage(context.TODO(), "", mustEncode(t, m))
	time.Sleep(1 * time.Millisecond)
	client := mockClient{instanceID1}
	ch, _ := broker.Register(context.TODO(), client.id)
	timer := time.NewTimer(2 * time.Second)
	for {
		select {
		case <-ch:
			return
		case <-timer.C:
			t.FailNow()
		}
	}
}

func TestBroker_PubkeyExtraction(t *testing.T) {
	broker := buildBroker(t, t.Name())
	broker.Start(context.TODO())
	inbox, _ := broker.Register(context.TODO(), instanceID1)
	sgn := signing.NewEdSigner()
	m := BuildPreRoundMsg(sgn, NewSetFromValues(value1), nil).Message
	m.InnerMsg.InstanceID = instanceID1

	broker.HandleMessage(context.TODO(), "", mustEncode(t, m))

	tm := time.NewTimer(2 * time.Second)
	for {
		select {
		case inMsg := <-inbox:
			assert.True(t, sgn.PublicKey().Equals(inMsg.PubKey))
			return
		case <-tm.C:
			t.Error("Timeout")
			t.FailNow()
			return
		}
	}
}

func Test_newMsg(t *testing.T) {
	m := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil).Message
	// TODO: remove this comment when ready
	//_, e := newMsg(m, MockStateQuerier{false, errors.New("my err")})
	//assert.NotNil(t, e)
	_, e := newMsg(context.TODO(), logtest.New(t), m, MockStateQuerier{true, nil})
	assert.Nil(t, e)
}

func TestBroker_updateInstance(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	r.Equal(types.NewLayerID(0), b.latestLayer)
	b.updateLatestLayer(context.TODO(), types.NewLayerID(1))
	r.Equal(types.NewLayerID(1), b.latestLayer)
	b.updateLatestLayer(context.TODO(), types.NewLayerID(2))
	r.Equal(types.NewLayerID(2), b.latestLayer)
}

func TestBroker_updateSynchronicity(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	b.isNodeSynced = trueFunc
	b.updateSynchronicity(context.TODO(), types.NewLayerID(1))
	r.True(b.isSynced(context.TODO(), types.NewLayerID(1)))
	b.isNodeSynced = falseFunc
	b.updateSynchronicity(context.TODO(), types.NewLayerID(1))
	r.True(b.isSynced(context.TODO(), types.NewLayerID(1)))
	b.updateSynchronicity(context.TODO(), types.NewLayerID(2))
	r.False(b.isSynced(context.TODO(), types.NewLayerID(2)))
}

func TestBroker_isSynced(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	b.isNodeSynced = trueFunc
	r.True(b.isSynced(context.TODO(), types.NewLayerID(1)))
	b.isNodeSynced = falseFunc
	r.True(b.isSynced(context.TODO(), types.NewLayerID(1)))
	r.False(b.isSynced(context.TODO(), types.NewLayerID(2)))
	b.isNodeSynced = trueFunc
	r.False(b.isSynced(context.TODO(), types.NewLayerID(2)))
}

func TestBroker_Register4(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	b.Start(context.TODO())
	b.isNodeSynced = trueFunc
	c, e := b.Register(context.TODO(), types.NewLayerID(1))
	r.Nil(e)
	r.Equal(b.outbox[1], c)

	b.isNodeSynced = falseFunc
	_, e = b.Register(context.TODO(), types.NewLayerID(2))
	r.NotNil(e)
}

func TestBroker_eventLoop(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	b.Start(context.TODO())

	// unknown-->invalid, ignore
	b.isNodeSynced = falseFunc
	m := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil).Message
	m.InnerMsg.InstanceID = instanceID1
	msg := newMockGossipMsg(m).Message
	b.HandleMessage(context.TODO(), "", mustEncode(t, msg))

	_, ok := b.outbox[instanceID1.Uint32()]
	r.False(ok)

	// register to invalid should error
	_, e := b.Register(context.TODO(), instanceID1)
	r.NotNil(e)

	// register to unknown->valid
	b.isNodeSynced = trueFunc
	c, e := b.Register(context.TODO(), instanceID2)
	r.Nil(e)
	m.InnerMsg.InstanceID = instanceID2
	msg = newMockGossipMsg(m).Message
	b.HandleMessage(context.TODO(), "", mustEncode(t, msg))
	recM := <-c
	r.Equal(msg, recM.Message)

	// unknown->valid early
	m.InnerMsg.InstanceID = instanceID3
	msg = newMockGossipMsg(m).Message
	b.HandleMessage(context.TODO(), "", mustEncode(t, msg))
	c, e = b.Register(context.TODO(), instanceID3)
	r.Nil(e)
	<-c
}

func TestBroker_eventLoop2(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	b.Start(context.TODO())

	// invalid instance
	b.isNodeSynced = falseFunc
	_, e := b.Register(context.TODO(), instanceID4)
	r.NotNil(e)
	m := BuildPreRoundMsg(signing.NewEdSigner(), NewSetFromValues(value1), nil).Message
	m.InnerMsg.InstanceID = instanceID4
	b.HandleMessage(context.TODO(), "", mustEncode(t, m))
	v, ok := b.syncState[instanceID4.Uint32()]
	r.True(ok)
	r.NotEqual(true, v)

	// valid but not early
	m.InnerMsg.InstanceID = instanceID6

	b.HandleMessage(context.TODO(), "", mustEncode(t, m))
	_, ok = b.outbox[instanceID6.Uint32()]
	r.False(ok)
}

func Test_validate(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())

	m := BuildStatusMsg(signing.NewEdSigner(), NewDefaultEmptySet())
	m.InnerMsg.InstanceID = types.NewLayerID(1)
	b.latestLayer = types.NewLayerID(2)
	e := b.validate(context.TODO(), m.Message)
	r.EqualError(e, errUnregistered.Error())

	m.InnerMsg.InstanceID = types.NewLayerID(2)
	e = b.validate(context.TODO(), m.Message)
	r.EqualError(e, errRegistration.Error())

	m.InnerMsg.InstanceID = types.NewLayerID(3)
	e = b.validate(context.TODO(), m.Message)
	r.EqualError(e, errEarlyMsg.Error())

	m.InnerMsg.InstanceID = types.NewLayerID(2)
	b.outbox[2] = make(chan *Msg)
	b.syncState[2] = false
	e = b.validate(context.TODO(), m.Message)
	r.EqualError(e, errNotSynced.Error())

	b.syncState[2] = true
	e = b.validate(context.TODO(), m.Message)
	r.Nil(e)
}

func TestBroker_clean(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())

	ten := types.NewLayerID(10)
	for i := types.NewLayerID(1); i.Before(ten); i = i.Add(1) {
		b.syncState[i.Uint32()] = true
	}

	b.latestLayer = ten.Sub(1)
	b.outbox[5] = make(chan *Msg)
	b.cleanOldLayers()
	r.Equal(types.NewLayerID(4), b.minDeleted)
	r.Equal(5, len(b.syncState))

	delete(b.outbox, 5)
	b.cleanOldLayers()
	r.Equal(1, len(b.syncState))
}

func TestBroker_Flow(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())

	b.Start(context.TODO())

	m := BuildStatusMsg(signing.NewEdSigner(), NewDefaultEmptySet())
	m.InnerMsg.InstanceID = types.NewLayerID(1)
	b.HandleMessage(context.TODO(), "", mustEncode(t, m.Message))

	ch1, e := b.Register(context.TODO(), types.NewLayerID(1))
	r.Nil(e)
	<-ch1

	m2 := BuildStatusMsg(signing.NewEdSigner(), NewDefaultEmptySet())
	m2.InnerMsg.InstanceID = types.NewLayerID(2)
	ch2, e := b.Register(context.TODO(), types.NewLayerID(2))
	r.Nil(e)

	b.HandleMessage(context.TODO(), "", mustEncode(t, m.Message))

	b.HandleMessage(context.TODO(), "", mustEncode(t, m2.Message))

	<-ch2
	<-ch1

	b.Register(context.TODO(), types.NewLayerID(3))
	b.Register(context.TODO(), types.NewLayerID(4))
	b.Unregister(context.TODO(), types.NewLayerID(2))
	r.Equal(instanceID0, b.minDeleted)

	// check still receiving msgs on ch1
	b.HandleMessage(context.TODO(), "", mustEncode(t, m.Message))
	<-ch1

	b.Unregister(context.TODO(), types.NewLayerID(1))
	r.Equal(instanceID2, b.minDeleted)
}

func TestBroker_Synced(t *testing.T) {
	r := require.New(t)
	b := buildBroker(t, t.Name())
	b.Start(context.TODO())
	wg := sync.WaitGroup{}
	for i := uint32(0); i < 1000; i++ {
		wg.Add(1)
		go func(j uint32) {
			r.True(b.Synced(context.TODO(), types.NewLayerID(j)))
			wg.Done()
		}(i)
	}

	wg.Wait()
}
