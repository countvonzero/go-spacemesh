// Code generated by MockGen. DO NOT EDIT.
// Source: ./tortoise.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	types "github.com/spacemeshos/go-spacemesh/common/types"
	result "github.com/spacemeshos/go-spacemesh/common/types/result"
	gomock "go.uber.org/mock/gomock"
)

// MockTortoise is a mock of Tortoise interface.
type MockTortoise struct {
	ctrl     *gomock.Controller
	recorder *MockTortoiseMockRecorder
}

// MockTortoiseMockRecorder is the mock recorder for MockTortoise.
type MockTortoiseMockRecorder struct {
	mock *MockTortoise
}

// NewMockTortoise creates a new mock instance.
func NewMockTortoise(ctrl *gomock.Controller) *MockTortoise {
	mock := &MockTortoise{ctrl: ctrl}
	mock.recorder = &MockTortoiseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTortoise) EXPECT() *MockTortoiseMockRecorder {
	return m.recorder
}

// LatestComplete mocks base method.
func (m *MockTortoise) LatestComplete() types.LayerID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LatestComplete")
	ret0, _ := ret[0].(types.LayerID)
	return ret0
}

// LatestComplete indicates an expected call of LatestComplete.
func (mr *MockTortoiseMockRecorder) LatestComplete() *TortoiseLatestCompleteCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LatestComplete", reflect.TypeOf((*MockTortoise)(nil).LatestComplete))
	return &TortoiseLatestCompleteCall{Call: call}
}

// TortoiseLatestCompleteCall wrap *gomock.Call
type TortoiseLatestCompleteCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseLatestCompleteCall) Return(arg0 types.LayerID) *TortoiseLatestCompleteCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseLatestCompleteCall) Do(f func() types.LayerID) *TortoiseLatestCompleteCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseLatestCompleteCall) DoAndReturn(f func() types.LayerID) *TortoiseLatestCompleteCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OnAtx mocks base method.
func (m *MockTortoise) OnAtx(arg0 *types.AtxTortoiseData) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnAtx", arg0)
}

// OnAtx indicates an expected call of OnAtx.
func (mr *MockTortoiseMockRecorder) OnAtx(arg0 interface{}) *TortoiseOnAtxCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnAtx", reflect.TypeOf((*MockTortoise)(nil).OnAtx), arg0)
	return &TortoiseOnAtxCall{Call: call}
}

// TortoiseOnAtxCall wrap *gomock.Call
type TortoiseOnAtxCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseOnAtxCall) Return() *TortoiseOnAtxCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseOnAtxCall) Do(f func(*types.AtxTortoiseData)) *TortoiseOnAtxCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseOnAtxCall) DoAndReturn(f func(*types.AtxTortoiseData)) *TortoiseOnAtxCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OnBlock mocks base method.
func (m *MockTortoise) OnBlock(arg0 types.BlockHeader) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnBlock", arg0)
}

// OnBlock indicates an expected call of OnBlock.
func (mr *MockTortoiseMockRecorder) OnBlock(arg0 interface{}) *TortoiseOnBlockCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnBlock", reflect.TypeOf((*MockTortoise)(nil).OnBlock), arg0)
	return &TortoiseOnBlockCall{Call: call}
}

// TortoiseOnBlockCall wrap *gomock.Call
type TortoiseOnBlockCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseOnBlockCall) Return() *TortoiseOnBlockCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseOnBlockCall) Do(f func(types.BlockHeader)) *TortoiseOnBlockCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseOnBlockCall) DoAndReturn(f func(types.BlockHeader)) *TortoiseOnBlockCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OnHareOutput mocks base method.
func (m *MockTortoise) OnHareOutput(arg0 types.LayerID, arg1 types.BlockID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnHareOutput", arg0, arg1)
}

// OnHareOutput indicates an expected call of OnHareOutput.
func (mr *MockTortoiseMockRecorder) OnHareOutput(arg0, arg1 interface{}) *TortoiseOnHareOutputCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnHareOutput", reflect.TypeOf((*MockTortoise)(nil).OnHareOutput), arg0, arg1)
	return &TortoiseOnHareOutputCall{Call: call}
}

// TortoiseOnHareOutputCall wrap *gomock.Call
type TortoiseOnHareOutputCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseOnHareOutputCall) Return() *TortoiseOnHareOutputCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseOnHareOutputCall) Do(f func(types.LayerID, types.BlockID)) *TortoiseOnHareOutputCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseOnHareOutputCall) DoAndReturn(f func(types.LayerID, types.BlockID)) *TortoiseOnHareOutputCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OnMalfeasance mocks base method.
func (m *MockTortoise) OnMalfeasance(arg0 types.NodeID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnMalfeasance", arg0)
}

// OnMalfeasance indicates an expected call of OnMalfeasance.
func (mr *MockTortoiseMockRecorder) OnMalfeasance(arg0 interface{}) *TortoiseOnMalfeasanceCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnMalfeasance", reflect.TypeOf((*MockTortoise)(nil).OnMalfeasance), arg0)
	return &TortoiseOnMalfeasanceCall{Call: call}
}

// TortoiseOnMalfeasanceCall wrap *gomock.Call
type TortoiseOnMalfeasanceCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseOnMalfeasanceCall) Return() *TortoiseOnMalfeasanceCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseOnMalfeasanceCall) Do(f func(types.NodeID)) *TortoiseOnMalfeasanceCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseOnMalfeasanceCall) DoAndReturn(f func(types.NodeID)) *TortoiseOnMalfeasanceCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// OnWeakCoin mocks base method.
func (m *MockTortoise) OnWeakCoin(arg0 types.LayerID, arg1 bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnWeakCoin", arg0, arg1)
}

// OnWeakCoin indicates an expected call of OnWeakCoin.
func (mr *MockTortoiseMockRecorder) OnWeakCoin(arg0, arg1 interface{}) *TortoiseOnWeakCoinCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnWeakCoin", reflect.TypeOf((*MockTortoise)(nil).OnWeakCoin), arg0, arg1)
	return &TortoiseOnWeakCoinCall{Call: call}
}

// TortoiseOnWeakCoinCall wrap *gomock.Call
type TortoiseOnWeakCoinCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseOnWeakCoinCall) Return() *TortoiseOnWeakCoinCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseOnWeakCoinCall) Do(f func(types.LayerID, bool)) *TortoiseOnWeakCoinCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseOnWeakCoinCall) DoAndReturn(f func(types.LayerID, bool)) *TortoiseOnWeakCoinCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Results mocks base method.
func (m *MockTortoise) Results(from, to types.LayerID) ([]result.Layer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Results", from, to)
	ret0, _ := ret[0].([]result.Layer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Results indicates an expected call of Results.
func (mr *MockTortoiseMockRecorder) Results(from, to interface{}) *TortoiseResultsCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Results", reflect.TypeOf((*MockTortoise)(nil).Results), from, to)
	return &TortoiseResultsCall{Call: call}
}

// TortoiseResultsCall wrap *gomock.Call
type TortoiseResultsCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseResultsCall) Return(arg0 []result.Layer, arg1 error) *TortoiseResultsCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseResultsCall) Do(f func(types.LayerID, types.LayerID) ([]result.Layer, error)) *TortoiseResultsCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseResultsCall) DoAndReturn(f func(types.LayerID, types.LayerID) ([]result.Layer, error)) *TortoiseResultsCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// TallyVotes mocks base method.
func (m *MockTortoise) TallyVotes(arg0 context.Context, arg1 types.LayerID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "TallyVotes", arg0, arg1)
}

// TallyVotes indicates an expected call of TallyVotes.
func (mr *MockTortoiseMockRecorder) TallyVotes(arg0, arg1 interface{}) *TortoiseTallyVotesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TallyVotes", reflect.TypeOf((*MockTortoise)(nil).TallyVotes), arg0, arg1)
	return &TortoiseTallyVotesCall{Call: call}
}

// TortoiseTallyVotesCall wrap *gomock.Call
type TortoiseTallyVotesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseTallyVotesCall) Return() *TortoiseTallyVotesCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseTallyVotesCall) Do(f func(context.Context, types.LayerID)) *TortoiseTallyVotesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseTallyVotesCall) DoAndReturn(f func(context.Context, types.LayerID)) *TortoiseTallyVotesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Updates mocks base method.
func (m *MockTortoise) Updates() []result.Layer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Updates")
	ret0, _ := ret[0].([]result.Layer)
	return ret0
}

// Updates indicates an expected call of Updates.
func (mr *MockTortoiseMockRecorder) Updates() *TortoiseUpdatesCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Updates", reflect.TypeOf((*MockTortoise)(nil).Updates))
	return &TortoiseUpdatesCall{Call: call}
}

// TortoiseUpdatesCall wrap *gomock.Call
type TortoiseUpdatesCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *TortoiseUpdatesCall) Return(arg0 []result.Layer) *TortoiseUpdatesCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *TortoiseUpdatesCall) Do(f func() []result.Layer) *TortoiseUpdatesCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *TortoiseUpdatesCall) DoAndReturn(f func() []result.Layer) *TortoiseUpdatesCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
