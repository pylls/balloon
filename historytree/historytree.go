/*
Package historytree implements part of Crosby's and Wallach's history tree data
structure, as presented in "Efficient Data Structures for Tamper-Evident Logging",
available at http://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf .
We provide membership proofs and omit incremental proofs and signing roots.
We also support computing the updated roots on the history tree based on a
membership proof that fixes the rest of the tree. See the Balloon paper for details.
*/
package historytree

import (
	"errors"
	"math"
	"strconv"

	"github.com/mndrix/ps"
	"github.com/pylls/balloon/util"
)

var prefixZero = []byte{0x0}
var prefixOne = []byte{0x1}

// Tree is a history tree.
type Tree struct {
	//frozen map[Position][]byte
	//events map[int][]byte
	frozen ps.Map
	events ps.Map
	size   int
}

// Position is a position in the tree.
type Position struct {
	Index, Layer int
}

func (p *Position) toString() string {
	return strconv.Itoa(p.Index) + "." + strconv.Itoa(p.Layer)
}

// ProofPosition is a position and its hash in the tree.
type ProofPosition struct {
	Hash []byte
	Position
}

// MembershipProof is a proof of membership of an event.
type MembershipProof struct {
	Nodes          []ProofPosition
	Index, Version int
	Event, Root    []byte
}

// NewTree returns a new history tree.
func NewTree() (t *Tree) {
	t = new(Tree)
	t.size = 0
	t.frozen = ps.NewMap()
	t.events = ps.NewMap()
	return
}

// Clone creates a copy of the history tree.
func (t *Tree) Clone() (clone *Tree) {
	clone = new(Tree)
	clone.size = t.size
	clone.frozen = t.frozen
	clone.events = t.events
	return
}

// layeR, Index, Version
// See Figure 5 in "Efficient Data Structures for Tamper-Evident Logging"
func (t *Tree) getHashedNode(index, layer, version int, proofMode bool) (value []byte, err error) {
	// always prefer frozen hashes, if we have calculated them
	if proofMode || version >= index+util.Pow(2, layer)-1 {
		if t.isFrozenHash(index, layer) {
			return t.getFrozenHash(index, layer)
		}
	}

	// special case for child nodes
	if layer == 0 && version >= index {
		event, err := t.getEvent(index)
		if err != nil {
			return nil, errors.New("no event with the provided index")
		}

		value = util.Hash(prefixZero, event)
		// have version determine if the right node is there or not
	} else if version >= index+util.Pow(2, layer-1) {
		a1, err := t.getHashedNode(index, layer-1, version, proofMode)
		if err != nil {
			return nil, errors.New("failed to get internal node with index " + strconv.Itoa(index))
		}
		a2, err := t.getHashedNode(index+util.Pow(2, layer-1), layer-1, version, proofMode)
		if err != nil {
			return nil, errors.New("failed to get internal node with index " + strconv.Itoa(index))
		}

		value = util.Hash(prefixOne, a1, a2)
	} else {
		a, err := t.getHashedNode(index, layer-1, version, proofMode)
		if err != nil {
			return nil, errors.New("failed to get internal node with index " + strconv.Itoa(index))
		}
		value = util.Hash(prefixOne, a)
	}

	// should we add this to the frozen hash cache?
	if version >= index+util.Pow(2, layer)-1 {
		t.setFrozenHash(index, layer, value)
	}

	return
}

func (t *Tree) isFrozenHash(index, layer int) bool {
	p := new(Position)
	p.Index = index
	p.Layer = layer
	_, exists := t.frozen.Lookup(p.toString())
	return exists
}

func (t *Tree) setFrozenHash(index, layer int, value []byte) {
	p := new(Position)
	p.Index = index
	p.Layer = layer
	t.frozen = t.frozen.Set(p.toString(), value)
}

func (t *Tree) getFrozenHash(index, layer int) (value []byte, err error) {
	p := new(Position)
	p.Index = index
	p.Layer = layer
	v, exists := t.frozen.Lookup(p.toString())
	if !exists {
		return nil, errors.New("no such frozen hash")
	}

	return v.([]byte), nil
}

// MembershipProof generates a membership proof.
func (t *Tree) MembershipProof(index, version int) (proof MembershipProof, err error) {
	if index < 0 || index >= t.Size() || index > version {
		return proof, errors.New("invalid index, has to be: 0 <= index <= version < size")
	}

	proof.Index = index
	proof.Version = version
	proof.Event, err = t.getEvent(index)
	if err != nil {
		return
	}
	proof.Root, err = t.getHashedNode(0, t.calculateDepth(version+1), version, false)
	if err != nil {
		return
	}

	// we know that the biggest possible proof is one node per layer
	proof.Nodes = make([]ProofPosition, 0, t.getDepth())
	err = t.membershipProof(index, 0, t.getDepth(), version, &proof)
	return
}

// the game is: walk the tree from the root to the target leaf
func (t *Tree) membershipProof(target, index, layer, version int, proof *MembershipProof) (err error) {
	if layer == 0 {
		return
	}
	// the number of events to the left of the node
	n := index + util.Pow(2, layer-1)
	if target < n {
		// go left, but should we save right first? We need to save right if there are any leaf nodes
		// fixed by the right node (otherwise we know it's hash is nil), dictated by the version of the
		// tree we are generating
		if version >= n {
			p := new(ProofPosition)
			p.Index = n
			p.Layer = layer - 1
			p.Hash, err = t.getHashedNode(p.Index, p.Layer, version, false)
			if err != nil {
				return
			}
			proof.Nodes = append(proof.Nodes, *p)
		}
		return t.membershipProof(target, index, layer-1, version, proof)
	}
	// go right, once we have saved the left node
	p := new(ProofPosition)
	p.Index = index
	p.Layer = layer - 1
	p.Hash, err = t.getHashedNode(p.Index, p.Layer, version, false)
	if err != nil {
		return
	}
	proof.Nodes = append(proof.Nodes, *p)

	return t.membershipProof(target, n, layer-1, version, proof)

}

// Verify verifies a membership proof
func (p *MembershipProof) Verify() (correct bool) {
	if p.Root == nil || p.Event == nil || p.Index < 0 ||
		p.Version < 0 {
		return false
	}

	proofTree := NewTree()
	for _, n := range p.Nodes {
		proofTree.frozen = proofTree.frozen.Set(n.Position.toString(), n.Hash)
	}
	proofTree.events = proofTree.events.Set(strconv.Itoa(p.Index), p.Event)

	c, err := proofTree.getHashedNode(0, proofTree.calculateDepth(p.Version+1), p.Version, true)
	if err != nil {
		return false
	}

	return util.Equal(c, p.Root)
}

func (t *Tree) getEvent(index int) (event []byte, err error) {
	e, exists := t.events.Lookup(strconv.Itoa(index))
	if !exists {
		return nil, errors.New("no such event")
	}
	return e.([]byte), nil
}

func (t *Tree) setEvent(index int, event []byte) (err error) {
	_, exists := t.events.Lookup(strconv.Itoa(index))
	if exists {
		return errors.New("there is already an event with that index")
	}
	t.events = t.events.Set(strconv.Itoa(index), event)
	t.size++
	return
}

func (t *Tree) getDepth() (depth int) {
	return t.calculateDepth(t.size)
}

func (t *Tree) calculateDepth(n int) (depth int) {
	if n == 0 {
		return 0
	}
	return int(math.Ceil(math.Log2(float64(n))))
}

// Size returns the number of events in the tree.
func (t *Tree) Size() int {
	return t.size
}

// LatestVersion returns the latest version of the tree.
func (t *Tree) LatestVersion() int {
	return t.size - 1
}

// Add adds an event to the history tree.
func (t *Tree) Add(event []byte) (root []byte, err error) {
	err = t.setEvent(t.Size(), event)
	if err != nil {
		return
	}
	// Since we use getDepth() here, inside it, the depth is already +1 due to
	// len(t.events) being +1 due to the SetEvent above. This means that we get
	// a growing tree that supports an arbitrary number of events, as noted by
	// Crosby and Wallach on page 6.
	return t.getHashedNode(0, t.getDepth(), t.Size()-1, false)
}

// Update calculates the updated history tree, represented by the valid membership
// proof for the latest event inserted into a history tree, by inserting the provided
// events. Returns the updated root, or an error.
func (p *MembershipProof) Update(events [][]byte) (root []byte, version int, err error) {
	proofTree := NewTree()

	// set all the nodes in the proof, we know they are all frozen
	// due to the membership proof being on the last inserted event
	for _, n := range p.Nodes {
		proofTree.frozen = proofTree.frozen.Set(n.Position.toString(), n.Hash)
	}

	// check if we are updating an empty history tree or not
	var startIndex int
	if len(p.Event) == 0 {
		proofTree.size = 0
		startIndex = 0
	} else {
		proofTree.size = p.Version + 1
		startIndex = p.Index + 1
		// set the event we are proving to and the size of the pruned tree
		// to the size of the actual tree
		proofTree.events = proofTree.events.Set(strconv.Itoa(p.Index), p.Event)
	}

	// add all events in order of the slice
	for i := 0; i < len(events); i++ {
		err = proofTree.setEvent(startIndex+i, events[i])
		if err != nil {
			return
		}
	}

	return proofTree.Root(), proofTree.Size() - 1, nil
}

// Root returns the current root of the tree.
func (t *Tree) Root() (c []byte) {
	if t.Size() > 0 {
		c, _ = t.getHashedNode(0, t.getDepth(), t.Size()-1, false)
	}
	return
}

// Size returns the size in bytes of a membership proof.
func (p *MembershipProof) Size() (bytes int) {
	bytes = 8 + 8 + len(p.Root) + len(p.Event)
	bytes = bytes + len(p.Nodes)*(16+util.HashOutputLen)
	return
}
