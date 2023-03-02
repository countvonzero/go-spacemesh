// Code generated by MockGen. DO NOT EDIT.
// Source: ./interfaces.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	types "github.com/spacemeshos/go-spacemesh/common/types"
)

// MocklayerPatrol is a mock of layerPatrol interface.
type MocklayerPatrol struct {
	ctrl     *gomock.Controller
	recorder *MocklayerPatrolMockRecorder
}

// MocklayerPatrolMockRecorder is the mock recorder for MocklayerPatrol.
type MocklayerPatrolMockRecorder struct {
	mock *MocklayerPatrol
}

// NewMocklayerPatrol creates a new mock instance.
func NewMocklayerPatrol(ctrl *gomock.Controller) *MocklayerPatrol {
	mock := &MocklayerPatrol{ctrl: ctrl}
	mock.recorder = &MocklayerPatrolMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MocklayerPatrol) EXPECT() *MocklayerPatrolMockRecorder {
	return m.recorder
}

// SetHareInCharge mocks base method.
func (m *MocklayerPatrol) SetHareInCharge(arg0 types.LayerID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetHareInCharge", arg0)
}

// SetHareInCharge indicates an expected call of SetHareInCharge.
func (mr *MocklayerPatrolMockRecorder) SetHareInCharge(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetHareInCharge", reflect.TypeOf((*MocklayerPatrol)(nil).SetHareInCharge), arg0)
}

// MockRolacle is a mock of Rolacle interface.
type MockRolacle struct {
	ctrl     *gomock.Controller
	recorder *MockRolacleMockRecorder
}

// MockRolacleMockRecorder is the mock recorder for MockRolacle.
type MockRolacleMockRecorder struct {
	mock *MockRolacle
}

// NewMockRolacle creates a new mock instance.
func NewMockRolacle(ctrl *gomock.Controller) *MockRolacle {
	mock := &MockRolacle{ctrl: ctrl}
	mock.recorder = &MockRolacleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRolacle) EXPECT() *MockRolacleMockRecorder {
	return m.recorder
}

// CalcEligibility mocks base method.
func (m *MockRolacle) CalcEligibility(arg0 context.Context, arg1 types.LayerID, arg2 uint32, arg3 int, arg4 types.NodeID, arg5 types.VRFPostIndex, arg6 []byte) (uint16, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CalcEligibility", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].(uint16)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CalcEligibility indicates an expected call of CalcEligibility.
func (mr *MockRolacleMockRecorder) CalcEligibility(arg0, arg1, arg2, arg3, arg4, arg5, arg6 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CalcEligibility", reflect.TypeOf((*MockRolacle)(nil).CalcEligibility), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// IsIdentityActiveOnConsensusView mocks base method.
func (m *MockRolacle) IsIdentityActiveOnConsensusView(arg0 context.Context, arg1 types.NodeID, arg2 types.LayerID) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsIdentityActiveOnConsensusView", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsIdentityActiveOnConsensusView indicates an expected call of IsIdentityActiveOnConsensusView.
func (mr *MockRolacleMockRecorder) IsIdentityActiveOnConsensusView(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsIdentityActiveOnConsensusView", reflect.TypeOf((*MockRolacle)(nil).IsIdentityActiveOnConsensusView), arg0, arg1, arg2)
}

// Proof mocks base method.
func (m *MockRolacle) Proof(arg0 context.Context, arg1 types.VRFPostIndex, arg2 types.LayerID, arg3 uint32) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Proof", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Proof indicates an expected call of Proof.
func (mr *MockRolacleMockRecorder) Proof(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Proof", reflect.TypeOf((*MockRolacle)(nil).Proof), arg0, arg1, arg2, arg3)
}

// Validate mocks base method.
func (m *MockRolacle) Validate(arg0 context.Context, arg1 types.LayerID, arg2 uint32, arg3 int, arg4 types.NodeID, arg5 []byte, arg6 uint16) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Validate", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Validate indicates an expected call of Validate.
func (mr *MockRolacleMockRecorder) Validate(arg0, arg1, arg2, arg3, arg4, arg5, arg6 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Validate", reflect.TypeOf((*MockRolacle)(nil).Validate), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// MockstateQuerier is a mock of stateQuerier interface.
type MockstateQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockstateQuerierMockRecorder
}

// MockstateQuerierMockRecorder is the mock recorder for MockstateQuerier.
type MockstateQuerierMockRecorder struct {
	mock *MockstateQuerier
}

// NewMockstateQuerier creates a new mock instance.
func NewMockstateQuerier(ctrl *gomock.Controller) *MockstateQuerier {
	mock := &MockstateQuerier{ctrl: ctrl}
	mock.recorder = &MockstateQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockstateQuerier) EXPECT() *MockstateQuerierMockRecorder {
	return m.recorder
}

// IsIdentityActiveOnConsensusView mocks base method.
func (m *MockstateQuerier) IsIdentityActiveOnConsensusView(arg0 context.Context, arg1 types.NodeID, arg2 types.LayerID) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsIdentityActiveOnConsensusView", arg0, arg1, arg2)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsIdentityActiveOnConsensusView indicates an expected call of IsIdentityActiveOnConsensusView.
func (mr *MockstateQuerierMockRecorder) IsIdentityActiveOnConsensusView(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsIdentityActiveOnConsensusView", reflect.TypeOf((*MockstateQuerier)(nil).IsIdentityActiveOnConsensusView), arg0, arg1, arg2)
}

// Mockmesh is a mock of mesh interface.
type Mockmesh struct {
	ctrl     *gomock.Controller
	recorder *MockmeshMockRecorder
}

// MockmeshMockRecorder is the mock recorder for Mockmesh.
type MockmeshMockRecorder struct {
	mock *Mockmesh
}

// NewMockmesh creates a new mock instance.
func NewMockmesh(ctrl *gomock.Controller) *Mockmesh {
	mock := &Mockmesh{ctrl: ctrl}
	mock.recorder = &MockmeshMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *Mockmesh) EXPECT() *MockmeshMockRecorder {
	return m.recorder
}

// AddMalfeasanceProof mocks base method.
func (m *Mockmesh) AddMalfeasanceProof(arg0 types.NodeID, arg1 *types.MalfeasanceProof) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddMalfeasanceProof", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddMalfeasanceProof indicates an expected call of AddMalfeasanceProof.
func (mr *MockmeshMockRecorder) AddMalfeasanceProof(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddMalfeasanceProof", reflect.TypeOf((*Mockmesh)(nil).AddMalfeasanceProof), arg0, arg1)
}

// Ballot mocks base method.
func (m *Mockmesh) Ballot(arg0 types.BallotID) (*types.Ballot, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ballot", arg0)
	ret0, _ := ret[0].(*types.Ballot)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Ballot indicates an expected call of Ballot.
func (mr *MockmeshMockRecorder) Ballot(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ballot", reflect.TypeOf((*Mockmesh)(nil).Ballot), arg0)
}

// EpochAtx mocks base method.
func (m *Mockmesh) EpochAtx(arg0 types.NodeID, arg1 types.EpochID) (*types.ActivationTxHeader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EpochAtx", arg0, arg1)
	ret0, _ := ret[0].(*types.ActivationTxHeader)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EpochAtx indicates an expected call of EpochAtx.
func (mr *MockmeshMockRecorder) EpochAtx(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EpochAtx", reflect.TypeOf((*Mockmesh)(nil).EpochAtx), arg0, arg1)
}

// GetMalfeasanceProof mocks base method.
func (m *Mockmesh) GetMalfeasanceProof(nodeID types.NodeID) (*types.MalfeasanceProof, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMalfeasanceProof", nodeID)
	ret0, _ := ret[0].(*types.MalfeasanceProof)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMalfeasanceProof indicates an expected call of GetMalfeasanceProof.
func (mr *MockmeshMockRecorder) GetMalfeasanceProof(nodeID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMalfeasanceProof", reflect.TypeOf((*Mockmesh)(nil).GetMalfeasanceProof), nodeID)
}

// Header mocks base method.
func (m *Mockmesh) Header(arg0 types.ATXID) (*types.ActivationTxHeader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Header", arg0)
	ret0, _ := ret[0].(*types.ActivationTxHeader)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Header indicates an expected call of Header.
func (mr *MockmeshMockRecorder) Header(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Header", reflect.TypeOf((*Mockmesh)(nil).Header), arg0)
}

// IsMalicious mocks base method.
func (m *Mockmesh) IsMalicious(arg0 types.NodeID) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMalicious", arg0)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsMalicious indicates an expected call of IsMalicious.
func (mr *MockmeshMockRecorder) IsMalicious(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMalicious", reflect.TypeOf((*Mockmesh)(nil).IsMalicious), arg0)
}

// Proposals mocks base method.
func (m *Mockmesh) Proposals(arg0 types.LayerID) ([]*types.Proposal, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Proposals", arg0)
	ret0, _ := ret[0].([]*types.Proposal)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Proposals indicates an expected call of Proposals.
func (mr *MockmeshMockRecorder) Proposals(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Proposals", reflect.TypeOf((*Mockmesh)(nil).Proposals), arg0)
}

// SetWeakCoin mocks base method.
func (m *Mockmesh) SetWeakCoin(arg0 types.LayerID, arg1 bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetWeakCoin", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetWeakCoin indicates an expected call of SetWeakCoin.
func (mr *MockmeshMockRecorder) SetWeakCoin(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetWeakCoin", reflect.TypeOf((*Mockmesh)(nil).SetWeakCoin), arg0, arg1)
}

// VRFNonce mocks base method.
func (m *Mockmesh) VRFNonce(arg0 types.NodeID, arg1 types.EpochID) (types.VRFPostIndex, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VRFNonce", arg0, arg1)
	ret0, _ := ret[0].(types.VRFPostIndex)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VRFNonce indicates an expected call of VRFNonce.
func (mr *MockmeshMockRecorder) VRFNonce(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VRFNonce", reflect.TypeOf((*Mockmesh)(nil).VRFNonce), arg0, arg1)
}
