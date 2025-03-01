// Code generated by MockGen. DO NOT EDIT.
// Source: ./beacons.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	fixed "github.com/spacemeshos/fixed"
	types "github.com/spacemeshos/go-spacemesh/common/types"
	gomock "go.uber.org/mock/gomock"
)

// MockBeaconCollector is a mock of BeaconCollector interface.
type MockBeaconCollector struct {
	ctrl     *gomock.Controller
	recorder *MockBeaconCollectorMockRecorder
}

// MockBeaconCollectorMockRecorder is the mock recorder for MockBeaconCollector.
type MockBeaconCollectorMockRecorder struct {
	mock *MockBeaconCollector
}

// NewMockBeaconCollector creates a new mock instance.
func NewMockBeaconCollector(ctrl *gomock.Controller) *MockBeaconCollector {
	mock := &MockBeaconCollector{ctrl: ctrl}
	mock.recorder = &MockBeaconCollectorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBeaconCollector) EXPECT() *MockBeaconCollectorMockRecorder {
	return m.recorder
}

// ReportBeaconFromBallot mocks base method.
func (m *MockBeaconCollector) ReportBeaconFromBallot(arg0 types.EpochID, arg1 *types.Ballot, arg2 types.Beacon, arg3 fixed.Fixed) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReportBeaconFromBallot", arg0, arg1, arg2, arg3)
}

// ReportBeaconFromBallot indicates an expected call of ReportBeaconFromBallot.
func (mr *MockBeaconCollectorMockRecorder) ReportBeaconFromBallot(arg0, arg1, arg2, arg3 interface{}) *BeaconCollectorReportBeaconFromBallotCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReportBeaconFromBallot", reflect.TypeOf((*MockBeaconCollector)(nil).ReportBeaconFromBallot), arg0, arg1, arg2, arg3)
	return &BeaconCollectorReportBeaconFromBallotCall{Call: call}
}

// BeaconCollectorReportBeaconFromBallotCall wrap *gomock.Call
type BeaconCollectorReportBeaconFromBallotCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *BeaconCollectorReportBeaconFromBallotCall) Return() *BeaconCollectorReportBeaconFromBallotCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *BeaconCollectorReportBeaconFromBallotCall) Do(f func(types.EpochID, *types.Ballot, types.Beacon, fixed.Fixed)) *BeaconCollectorReportBeaconFromBallotCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *BeaconCollectorReportBeaconFromBallotCall) DoAndReturn(f func(types.EpochID, *types.Ballot, types.Beacon, fixed.Fixed)) *BeaconCollectorReportBeaconFromBallotCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockBeaconGetter is a mock of BeaconGetter interface.
type MockBeaconGetter struct {
	ctrl     *gomock.Controller
	recorder *MockBeaconGetterMockRecorder
}

// MockBeaconGetterMockRecorder is the mock recorder for MockBeaconGetter.
type MockBeaconGetterMockRecorder struct {
	mock *MockBeaconGetter
}

// NewMockBeaconGetter creates a new mock instance.
func NewMockBeaconGetter(ctrl *gomock.Controller) *MockBeaconGetter {
	mock := &MockBeaconGetter{ctrl: ctrl}
	mock.recorder = &MockBeaconGetterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBeaconGetter) EXPECT() *MockBeaconGetterMockRecorder {
	return m.recorder
}

// GetBeacon mocks base method.
func (m *MockBeaconGetter) GetBeacon(arg0 types.EpochID) (types.Beacon, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBeacon", arg0)
	ret0, _ := ret[0].(types.Beacon)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBeacon indicates an expected call of GetBeacon.
func (mr *MockBeaconGetterMockRecorder) GetBeacon(arg0 interface{}) *BeaconGetterGetBeaconCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBeacon", reflect.TypeOf((*MockBeaconGetter)(nil).GetBeacon), arg0)
	return &BeaconGetterGetBeaconCall{Call: call}
}

// BeaconGetterGetBeaconCall wrap *gomock.Call
type BeaconGetterGetBeaconCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *BeaconGetterGetBeaconCall) Return(arg0 types.Beacon, arg1 error) *BeaconGetterGetBeaconCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *BeaconGetterGetBeaconCall) Do(f func(types.EpochID) (types.Beacon, error)) *BeaconGetterGetBeaconCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *BeaconGetterGetBeaconCall) DoAndReturn(f func(types.EpochID) (types.Beacon, error)) *BeaconGetterGetBeaconCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
