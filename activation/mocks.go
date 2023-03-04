// Code generated by MockGen. DO NOT EDIT.
// Source: ./interface.go

// Package activation is a generated GoMock package.
package activation

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	types "github.com/spacemeshos/go-spacemesh/common/types"
)

// MockAtxReceiver is a mock of AtxReceiver interface.
type MockAtxReceiver struct {
	ctrl     *gomock.Controller
	recorder *MockAtxReceiverMockRecorder
}

// MockAtxReceiverMockRecorder is the mock recorder for MockAtxReceiver.
type MockAtxReceiverMockRecorder struct {
	mock *MockAtxReceiver
}

// NewMockAtxReceiver creates a new mock instance.
func NewMockAtxReceiver(ctrl *gomock.Controller) *MockAtxReceiver {
	mock := &MockAtxReceiver{ctrl: ctrl}
	mock.recorder = &MockAtxReceiverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAtxReceiver) EXPECT() *MockAtxReceiverMockRecorder {
	return m.recorder
}

// OnAtx mocks base method.
func (m *MockAtxReceiver) OnAtx(arg0 *types.ActivationTxHeader) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnAtx", arg0)
}

// OnAtx indicates an expected call of OnAtx.
func (mr *MockAtxReceiverMockRecorder) OnAtx(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnAtx", reflect.TypeOf((*MockAtxReceiver)(nil).OnAtx), arg0)
}

// MocknipostValidator is a mock of nipostValidator interface.
type MocknipostValidator struct {
	ctrl     *gomock.Controller
	recorder *MocknipostValidatorMockRecorder
}

// MocknipostValidatorMockRecorder is the mock recorder for MocknipostValidator.
type MocknipostValidatorMockRecorder struct {
	mock *MocknipostValidator
}

// NewMocknipostValidator creates a new mock instance.
func NewMocknipostValidator(ctrl *gomock.Controller) *MocknipostValidator {
	mock := &MocknipostValidator{ctrl: ctrl}
	mock.recorder = &MocknipostValidatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocknipostValidator) EXPECT() *MocknipostValidatorMockRecorder {
	return m.recorder
}

// InitialNIPostChallenge mocks base method.
func (m *MocknipostValidator) InitialNIPostChallenge(challenge *types.NIPostChallenge, atxs atxProvider, goldenATXID types.ATXID, expectedPostIndices []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitialNIPostChallenge", challenge, atxs, goldenATXID, expectedPostIndices)
	ret0, _ := ret[0].(error)
	return ret0
}

// InitialNIPostChallenge indicates an expected call of InitialNIPostChallenge.
func (mr *MocknipostValidatorMockRecorder) InitialNIPostChallenge(challenge, atxs, goldenATXID, expectedPostIndices interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitialNIPostChallenge", reflect.TypeOf((*MocknipostValidator)(nil).InitialNIPostChallenge), challenge, atxs, goldenATXID, expectedPostIndices)
}

// NIPost mocks base method.
func (m *MocknipostValidator) NIPost(nodeId types.NodeID, atxId types.ATXID, NIPost *types.NIPost, expectedChallenge types.Hash32, numUnits uint32) (uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NIPost", nodeId, atxId, NIPost, expectedChallenge, numUnits)
	ret0, _ := ret[0].(uint64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NIPost indicates an expected call of NIPost.
func (mr *MocknipostValidatorMockRecorder) NIPost(nodeId, atxId, NIPost, expectedChallenge, numUnits interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NIPost", reflect.TypeOf((*MocknipostValidator)(nil).NIPost), nodeId, atxId, NIPost, expectedChallenge, numUnits)
}

// NIPostChallenge mocks base method.
func (m *MocknipostValidator) NIPostChallenge(challenge *types.NIPostChallenge, atxs atxProvider, nodeID types.NodeID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NIPostChallenge", challenge, atxs, nodeID)
	ret0, _ := ret[0].(error)
	return ret0
}

// NIPostChallenge indicates an expected call of NIPostChallenge.
func (mr *MocknipostValidatorMockRecorder) NIPostChallenge(challenge, atxs, nodeID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NIPostChallenge", reflect.TypeOf((*MocknipostValidator)(nil).NIPostChallenge), challenge, atxs, nodeID)
}

// NumUnits mocks base method.
func (m *MocknipostValidator) NumUnits(cfg *PostConfig, numUnits uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NumUnits", cfg, numUnits)
	ret0, _ := ret[0].(error)
	return ret0
}

// NumUnits indicates an expected call of NumUnits.
func (mr *MocknipostValidatorMockRecorder) NumUnits(cfg, numUnits interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NumUnits", reflect.TypeOf((*MocknipostValidator)(nil).NumUnits), cfg, numUnits)
}

// PositioningAtx mocks base method.
func (m *MocknipostValidator) PositioningAtx(id *types.ATXID, atxs atxProvider, goldenATXID types.ATXID, publayer types.LayerID, layersPerEpoch uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PositioningAtx", id, atxs, goldenATXID, publayer, layersPerEpoch)
	ret0, _ := ret[0].(error)
	return ret0
}

// PositioningAtx indicates an expected call of PositioningAtx.
func (mr *MocknipostValidatorMockRecorder) PositioningAtx(id, atxs, goldenATXID, publayer, layersPerEpoch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PositioningAtx", reflect.TypeOf((*MocknipostValidator)(nil).PositioningAtx), id, atxs, goldenATXID, publayer, layersPerEpoch)
}

// Post mocks base method.
func (m *MocknipostValidator) Post(nodeId types.NodeID, atxId types.ATXID, Post *types.Post, PostMetadata *types.PostMetadata, numUnits uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Post", nodeId, atxId, Post, PostMetadata, numUnits)
	ret0, _ := ret[0].(error)
	return ret0
}

// Post indicates an expected call of Post.
func (mr *MocknipostValidatorMockRecorder) Post(nodeId, atxId, Post, PostMetadata, numUnits interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Post", reflect.TypeOf((*MocknipostValidator)(nil).Post), nodeId, atxId, Post, PostMetadata, numUnits)
}

// PostMetadata mocks base method.
func (m *MocknipostValidator) PostMetadata(cfg *PostConfig, metadata *types.PostMetadata) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostMetadata", cfg, metadata)
	ret0, _ := ret[0].(error)
	return ret0
}

// PostMetadata indicates an expected call of PostMetadata.
func (mr *MocknipostValidatorMockRecorder) PostMetadata(cfg, metadata interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostMetadata", reflect.TypeOf((*MocknipostValidator)(nil).PostMetadata), cfg, metadata)
}

// VRFNonce mocks base method.
func (m *MocknipostValidator) VRFNonce(nodeId types.NodeID, commitmentAtxId types.ATXID, vrfNonce *types.VRFPostIndex, PostMetadata *types.PostMetadata, numUnits uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VRFNonce", nodeId, commitmentAtxId, vrfNonce, PostMetadata, numUnits)
	ret0, _ := ret[0].(error)
	return ret0
}

// VRFNonce indicates an expected call of VRFNonce.
func (mr *MocknipostValidatorMockRecorder) VRFNonce(nodeId, commitmentAtxId, vrfNonce, PostMetadata, numUnits interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VRFNonce", reflect.TypeOf((*MocknipostValidator)(nil).VRFNonce), nodeId, commitmentAtxId, vrfNonce, PostMetadata, numUnits)
}

// MocklayerClock is a mock of layerClock interface.
type MocklayerClock struct {
	ctrl     *gomock.Controller
	recorder *MocklayerClockMockRecorder
}

// MocklayerClockMockRecorder is the mock recorder for MocklayerClock.
type MocklayerClockMockRecorder struct {
	mock *MocklayerClock
}

// NewMocklayerClock creates a new mock instance.
func NewMocklayerClock(ctrl *gomock.Controller) *MocklayerClock {
	mock := &MocklayerClock{ctrl: ctrl}
	mock.recorder = &MocklayerClockMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocklayerClock) EXPECT() *MocklayerClockMockRecorder {
	return m.recorder
}

// AwaitLayer mocks base method.
func (m *MocklayerClock) AwaitLayer(layerID types.LayerID) chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AwaitLayer", layerID)
	ret0, _ := ret[0].(chan struct{})
	return ret0
}

// AwaitLayer indicates an expected call of AwaitLayer.
func (mr *MocklayerClockMockRecorder) AwaitLayer(layerID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AwaitLayer", reflect.TypeOf((*MocklayerClock)(nil).AwaitLayer), layerID)
}

// CurrentLayer mocks base method.
func (m *MocklayerClock) CurrentLayer() types.LayerID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CurrentLayer")
	ret0, _ := ret[0].(types.LayerID)
	return ret0
}

// CurrentLayer indicates an expected call of CurrentLayer.
func (mr *MocklayerClockMockRecorder) CurrentLayer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CurrentLayer", reflect.TypeOf((*MocklayerClock)(nil).CurrentLayer))
}

// LayerToTime mocks base method.
func (m *MocklayerClock) LayerToTime(arg0 types.LayerID) time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LayerToTime", arg0)
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// LayerToTime indicates an expected call of LayerToTime.
func (mr *MocklayerClockMockRecorder) LayerToTime(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LayerToTime", reflect.TypeOf((*MocklayerClock)(nil).LayerToTime), arg0)
}

// MocknipostBuilder is a mock of nipostBuilder interface.
type MocknipostBuilder struct {
	ctrl     *gomock.Controller
	recorder *MocknipostBuilderMockRecorder
}

// MocknipostBuilderMockRecorder is the mock recorder for MocknipostBuilder.
type MocknipostBuilderMockRecorder struct {
	mock *MocknipostBuilder
}

// NewMocknipostBuilder creates a new mock instance.
func NewMocknipostBuilder(ctrl *gomock.Controller) *MocknipostBuilder {
	mock := &MocknipostBuilder{ctrl: ctrl}
	mock.recorder = &MocknipostBuilderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocknipostBuilder) EXPECT() *MocknipostBuilderMockRecorder {
	return m.recorder
}

// BuildNIPost mocks base method.
func (m *MocknipostBuilder) BuildNIPost(ctx context.Context, challenge *types.PoetChallenge) (*types.NIPost, time.Duration, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildNIPost", ctx, challenge)
	ret0, _ := ret[0].(*types.NIPost)
	ret1, _ := ret[1].(time.Duration)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// BuildNIPost indicates an expected call of BuildNIPost.
func (mr *MocknipostBuilderMockRecorder) BuildNIPost(ctx, challenge interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildNIPost", reflect.TypeOf((*MocknipostBuilder)(nil).BuildNIPost), ctx, challenge)
}

// UpdatePoETProvers mocks base method.
func (m *MocknipostBuilder) UpdatePoETProvers(arg0 []PoetProvingServiceClient) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UpdatePoETProvers", arg0)
}

// UpdatePoETProvers indicates an expected call of UpdatePoETProvers.
func (mr *MocknipostBuilderMockRecorder) UpdatePoETProvers(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdatePoETProvers", reflect.TypeOf((*MocknipostBuilder)(nil).UpdatePoETProvers), arg0)
}

// MockatxHandler is a mock of atxHandler interface.
type MockatxHandler struct {
	ctrl     *gomock.Controller
	recorder *MockatxHandlerMockRecorder
}

// MockatxHandlerMockRecorder is the mock recorder for MockatxHandler.
type MockatxHandlerMockRecorder struct {
	mock *MockatxHandler
}

// NewMockatxHandler creates a new mock instance.
func NewMockatxHandler(ctrl *gomock.Controller) *MockatxHandler {
	mock := &MockatxHandler{ctrl: ctrl}
	mock.recorder = &MockatxHandlerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockatxHandler) EXPECT() *MockatxHandlerMockRecorder {
	return m.recorder
}

// AwaitAtx mocks base method.
func (m *MockatxHandler) AwaitAtx(id types.ATXID) chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AwaitAtx", id)
	ret0, _ := ret[0].(chan struct{})
	return ret0
}

// AwaitAtx indicates an expected call of AwaitAtx.
func (mr *MockatxHandlerMockRecorder) AwaitAtx(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AwaitAtx", reflect.TypeOf((*MockatxHandler)(nil).AwaitAtx), id)
}

// GetPosAtxID mocks base method.
func (m *MockatxHandler) GetPosAtxID() (types.ATXID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPosAtxID")
	ret0, _ := ret[0].(types.ATXID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPosAtxID indicates an expected call of GetPosAtxID.
func (mr *MockatxHandlerMockRecorder) GetPosAtxID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPosAtxID", reflect.TypeOf((*MockatxHandler)(nil).GetPosAtxID))
}

// UnsubscribeAtx mocks base method.
func (m *MockatxHandler) UnsubscribeAtx(id types.ATXID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "UnsubscribeAtx", id)
}

// UnsubscribeAtx indicates an expected call of UnsubscribeAtx.
func (mr *MockatxHandlerMockRecorder) UnsubscribeAtx(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnsubscribeAtx", reflect.TypeOf((*MockatxHandler)(nil).UnsubscribeAtx), id)
}

// Mocksigner is a mock of signer interface.
type Mocksigner struct {
	ctrl     *gomock.Controller
	recorder *MocksignerMockRecorder
}

// MocksignerMockRecorder is the mock recorder for Mocksigner.
type MocksignerMockRecorder struct {
	mock *Mocksigner
}

// NewMocksigner creates a new mock instance.
func NewMocksigner(ctrl *gomock.Controller) *Mocksigner {
	mock := &Mocksigner{ctrl: ctrl}
	mock.recorder = &MocksignerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mocksigner) EXPECT() *MocksignerMockRecorder {
	return m.recorder
}

// NodeID mocks base method.
func (m *Mocksigner) NodeID() types.NodeID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NodeID")
	ret0, _ := ret[0].(types.NodeID)
	return ret0
}

// NodeID indicates an expected call of NodeID.
func (mr *MocksignerMockRecorder) NodeID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NodeID", reflect.TypeOf((*Mocksigner)(nil).NodeID))
}

// Sign mocks base method.
func (m *Mocksigner) Sign(arg0 []byte) []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sign", arg0)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Sign indicates an expected call of Sign.
func (mr *MocksignerMockRecorder) Sign(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sign", reflect.TypeOf((*Mocksigner)(nil).Sign), arg0)
}

// MockkeyExtractor is a mock of keyExtractor interface.
type MockkeyExtractor struct {
	ctrl     *gomock.Controller
	recorder *MockkeyExtractorMockRecorder
}

// MockkeyExtractorMockRecorder is the mock recorder for MockkeyExtractor.
type MockkeyExtractorMockRecorder struct {
	mock *MockkeyExtractor
}

// NewMockkeyExtractor creates a new mock instance.
func NewMockkeyExtractor(ctrl *gomock.Controller) *MockkeyExtractor {
	mock := &MockkeyExtractor{ctrl: ctrl}
	mock.recorder = &MockkeyExtractorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockkeyExtractor) EXPECT() *MockkeyExtractorMockRecorder {
	return m.recorder
}

// ExtractNodeID mocks base method.
func (m_2 *MockkeyExtractor) ExtractNodeID(m, sig []byte) (types.NodeID, error) {
	m_2.ctrl.T.Helper()
	ret := m_2.ctrl.Call(m_2, "ExtractNodeID", m, sig)
	ret0, _ := ret[0].(types.NodeID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExtractNodeID indicates an expected call of ExtractNodeID.
func (mr *MockkeyExtractorMockRecorder) ExtractNodeID(m, sig interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExtractNodeID", reflect.TypeOf((*MockkeyExtractor)(nil).ExtractNodeID), m, sig)
}

// Mocksyncer is a mock of syncer interface.
type Mocksyncer struct {
	ctrl     *gomock.Controller
	recorder *MocksyncerMockRecorder
}

// MocksyncerMockRecorder is the mock recorder for Mocksyncer.
type MocksyncerMockRecorder struct {
	mock *Mocksyncer
}

// NewMocksyncer creates a new mock instance.
func NewMocksyncer(ctrl *gomock.Controller) *Mocksyncer {
	mock := &Mocksyncer{ctrl: ctrl}
	mock.recorder = &MocksyncerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mocksyncer) EXPECT() *MocksyncerMockRecorder {
	return m.recorder
}

// RegisterForATXSynced mocks base method.
func (m *Mocksyncer) RegisterForATXSynced() chan struct{} {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterForATXSynced")
	ret0, _ := ret[0].(chan struct{})
	return ret0
}

// RegisterForATXSynced indicates an expected call of RegisterForATXSynced.
func (mr *MocksyncerMockRecorder) RegisterForATXSynced() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterForATXSynced", reflect.TypeOf((*Mocksyncer)(nil).RegisterForATXSynced))
}

// MockatxProvider is a mock of atxProvider interface.
type MockatxProvider struct {
	ctrl     *gomock.Controller
	recorder *MockatxProviderMockRecorder
}

// MockatxProviderMockRecorder is the mock recorder for MockatxProvider.
type MockatxProviderMockRecorder struct {
	mock *MockatxProvider
}

// NewMockatxProvider creates a new mock instance.
func NewMockatxProvider(ctrl *gomock.Controller) *MockatxProvider {
	mock := &MockatxProvider{ctrl: ctrl}
	mock.recorder = &MockatxProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockatxProvider) EXPECT() *MockatxProviderMockRecorder {
	return m.recorder
}

// GetAtxHeader mocks base method.
func (m *MockatxProvider) GetAtxHeader(id types.ATXID) (*types.ActivationTxHeader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAtxHeader", id)
	ret0, _ := ret[0].(*types.ActivationTxHeader)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAtxHeader indicates an expected call of GetAtxHeader.
func (mr *MockatxProviderMockRecorder) GetAtxHeader(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAtxHeader", reflect.TypeOf((*MockatxProvider)(nil).GetAtxHeader), id)
}

// MockpostSetupProvider is a mock of postSetupProvider interface.
type MockpostSetupProvider struct {
	ctrl     *gomock.Controller
	recorder *MockpostSetupProviderMockRecorder
}

// MockpostSetupProviderMockRecorder is the mock recorder for MockpostSetupProvider.
type MockpostSetupProviderMockRecorder struct {
	mock *MockpostSetupProvider
}

// NewMockpostSetupProvider creates a new mock instance.
func NewMockpostSetupProvider(ctrl *gomock.Controller) *MockpostSetupProvider {
	mock := &MockpostSetupProvider{ctrl: ctrl}
	mock.recorder = &MockpostSetupProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockpostSetupProvider) EXPECT() *MockpostSetupProviderMockRecorder {
	return m.recorder
}

// Benchmark mocks base method.
func (m *MockpostSetupProvider) Benchmark(p PostSetupComputeProvider) (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Benchmark", p)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Benchmark indicates an expected call of Benchmark.
func (mr *MockpostSetupProviderMockRecorder) Benchmark(p interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Benchmark", reflect.TypeOf((*MockpostSetupProvider)(nil).Benchmark), p)
}

// ComputeProviders mocks base method.
func (m *MockpostSetupProvider) ComputeProviders() []PostSetupComputeProvider {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ComputeProviders")
	ret0, _ := ret[0].([]PostSetupComputeProvider)
	return ret0
}

// ComputeProviders indicates an expected call of ComputeProviders.
func (mr *MockpostSetupProviderMockRecorder) ComputeProviders() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ComputeProviders", reflect.TypeOf((*MockpostSetupProvider)(nil).ComputeProviders))
}

// Config mocks base method.
func (m *MockpostSetupProvider) Config() PostConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Config")
	ret0, _ := ret[0].(PostConfig)
	return ret0
}

// Config indicates an expected call of Config.
func (mr *MockpostSetupProviderMockRecorder) Config() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Config", reflect.TypeOf((*MockpostSetupProvider)(nil).Config))
}

// GenerateProof mocks base method.
func (m *MockpostSetupProvider) GenerateProof(ctx context.Context, challenge []byte) (*types.Post, *types.PostMetadata, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateProof", ctx, challenge)
	ret0, _ := ret[0].(*types.Post)
	ret1, _ := ret[1].(*types.PostMetadata)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GenerateProof indicates an expected call of GenerateProof.
func (mr *MockpostSetupProviderMockRecorder) GenerateProof(ctx, challenge interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateProof", reflect.TypeOf((*MockpostSetupProvider)(nil).GenerateProof), ctx, challenge)
}

// LastOpts mocks base method.
func (m *MockpostSetupProvider) LastOpts() *PostSetupOpts {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LastOpts")
	ret0, _ := ret[0].(*PostSetupOpts)
	return ret0
}

// LastOpts indicates an expected call of LastOpts.
func (mr *MockpostSetupProviderMockRecorder) LastOpts() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LastOpts", reflect.TypeOf((*MockpostSetupProvider)(nil).LastOpts))
}

// Reset mocks base method.
func (m *MockpostSetupProvider) Reset() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Reset")
	ret0, _ := ret[0].(error)
	return ret0
}

// Reset indicates an expected call of Reset.
func (mr *MockpostSetupProviderMockRecorder) Reset() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Reset", reflect.TypeOf((*MockpostSetupProvider)(nil).Reset))
}

// StartSession mocks base method.
func (m *MockpostSetupProvider) StartSession(context context.Context, opts PostSetupOpts, commitmentAtx types.ATXID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartSession", context, opts, commitmentAtx)
	ret0, _ := ret[0].(error)
	return ret0
}

// StartSession indicates an expected call of StartSession.
func (mr *MockpostSetupProviderMockRecorder) StartSession(context, opts, commitmentAtx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartSession", reflect.TypeOf((*MockpostSetupProvider)(nil).StartSession), context, opts, commitmentAtx)
}

// Status mocks base method.
func (m *MockpostSetupProvider) Status() *PostSetupStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(*PostSetupStatus)
	return ret0
}

// Status indicates an expected call of Status.
func (mr *MockpostSetupProviderMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockpostSetupProvider)(nil).Status))
}

// VRFNonce mocks base method.
func (m *MockpostSetupProvider) VRFNonce() (*types.VRFPostIndex, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VRFNonce")
	ret0, _ := ret[0].(*types.VRFPostIndex)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VRFNonce indicates an expected call of VRFNonce.
func (mr *MockpostSetupProviderMockRecorder) VRFNonce() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VRFNonce", reflect.TypeOf((*MockpostSetupProvider)(nil).VRFNonce))
}
