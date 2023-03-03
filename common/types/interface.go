package types

type keyExtractor interface {
	ExtractNodeID(msg, sig []byte) (NodeID, error)
}
