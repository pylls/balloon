package historytree

import (
	"bytes"
	"testing"

	"github.com/pylls/balloon/util"
)

func TestEmpty(t *testing.T) {
	tree := NewTree()
	if tree.Size() != 0 {
		t.Fatalf("an empty tree reported size %d, expected 0", tree.Size())
	}
	if tree.LatestVersion() >= 0 {
		t.Fatalf("expected a non-negative version, got %d", tree.LatestVersion())
	}
}

func TestAdd(t *testing.T) {
	tree := NewTree()
	event0 := util.Hash([]byte("event 0"))
	event1 := util.Hash([]byte("event 1"))
	event2 := util.Hash([]byte("event 2"))
	event3 := util.Hash([]byte("event 3"))
	event4 := util.Hash([]byte("event 4"))

	c, err := tree.Add(event0)
	if err != nil {
		t.Fatalf("failed to add event to empty tree, error: %s", err)
	}

	// should be that c == H(0||event0)
	if !bytes.Equal(c, util.Hash(prefixZero, event0)) {
		t.Fatalf("the returned root for the first event is invalid")
	}

	c, err = tree.Add(event1)
	if err != nil {
		t.Fatalf("failed to add event to tree of size %d, error: %s", tree.Size(), err)
	}

	// should be that c == H(1||H(0||event0)||H(0||event1))
	if !bytes.Equal(c, util.Hash(prefixOne, util.Hash(prefixZero, event0),
		util.Hash(prefixZero, event1))) {
		t.Fatalf("the returned root for the second event is invalid, %d, %d",
			tree.getDepth(), tree.Size()-1)
	}
	c, err = tree.Add(event2)
	if err != nil {
		t.Fatalf("failed to add event to tree of size %d, error: %s", tree.Size(), err)
	}

	// should be that c == H(1||H(1||H(0||event0)||H(0||event1))||H(1||H(0||event2)))
	if !bytes.Equal(c, util.Hash(prefixOne,
		util.Hash(prefixOne, util.Hash(prefixZero, event0), util.Hash(prefixZero, event1)),
		util.Hash(prefixOne, util.Hash(prefixZero, event2)))) {
		t.Fatalf("the returned root for the third event is invalid, %d, %d",
			tree.getDepth(), tree.Size()-1)
	}

	c, err = tree.Add(event3)
	if err != nil {
		t.Fatalf("failed to add event to tree of size %d, error: %s", tree.Size(), err)
	}

	// should be that c == H(1||H(1||H(0||event0)||H(0||event1))
	// 						  ||H(1||H(0||event2)||H(0||event3)))
	if !bytes.Equal(c, util.Hash(prefixOne,
		util.Hash(prefixOne, util.Hash(prefixZero, event0),
			util.Hash(prefixZero, event1)),
		util.Hash(prefixOne, util.Hash(prefixZero, event2),
			util.Hash(prefixZero, event3)))) {
		t.Fatalf("the returned root for the fourth event is invalid, %d, %d",
			tree.getDepth(), tree.Size()-1)
	}

	c, err = tree.Add(event4)
	if err != nil {
		t.Fatalf("failed to add event to tree of size %d, error: %s", tree.Size(), err)
	}

	// should be that c == H(1||x||y), where
	// x = H(1||H(1||H(0||event0)||H(0||event1))
	// 		  ||H(1||H(0||event2)||H(0||event3)))
	// y = H(1||H(1||H(0||event4)))
	x := util.Hash(prefixOne,
		util.Hash(prefixOne, util.Hash(prefixZero, event0), util.Hash(prefixZero, event1)),
		util.Hash(prefixOne, util.Hash(prefixZero, event2), util.Hash(prefixZero, event3)))
	y := util.Hash(prefixOne, util.Hash(prefixOne, util.Hash(prefixZero, event4)))
	if !bytes.Equal(c, util.Hash(prefixOne, x, y)) {
		t.Fatalf("failed to add event to tree of size %d, error: %s", tree.Size(), err)
	}
}

func TestMembershipQuery(t *testing.T) {
	size := 128
	tree := NewTree()
	events := make([][]byte, size)
	roots := make([][]byte, size)
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		root, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
		if root == nil {
			t.Fatal("got empty root for non-empty root")
		}
		roots[i] = root
	}

	for i := 0; i < size; i++ {
		for j := 0; j < i; j++ {
			proof, err := tree.MembershipProof(j, i-1)
			if err != nil {
				t.Fatalf("failed to create a membership proof: %s", err)
			}
			if proof.Index != j || proof.Version != i-1 ||
				!bytes.Equal(proof.Root, roots[i-1]) ||
				!bytes.Equal(proof.Event, events[j]) {
				t.Fatal("invalid parameters in proof")
			}
			if !proof.Verify() {
				t.Fatalf("failed to verify membership proof for target %d", j)
			}
			if proof.Size() == 0 {
				t.Fatal("expected non-zero proof size")
			}
		}
		_, err := tree.MembershipProof(i, i-1)
		if err == nil {
			t.Fatal("successfully generated a membership proof for index > version")
		}
	}
}

func TestFlipMembershipProof(t *testing.T) {
	// create a tree and a valid proof to test
	size := 128
	tree := NewTree()
	events := make([][]byte, size)
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}
	proof, err := tree.MembershipProof(size-1, size-1)
	if err != nil {
		t.Fatalf("failed to create a membership proof: %s", err)
	}
	if !proof.Verify() {
		t.Fatalf("failed to verify membership proof")
	}

	// flip index
	proof.Index++
	if proof.Verify() {
		t.Fatal("verified an invalid proof and/or argument")
	}
	proof.Index--

	// flip version
	proof.Version++
	if proof.Verify() {
		t.Fatal("verified an invalid proof and/or argument")
	}
	proof.Version--

	event := proof.Event
	proof.Event = nil
	if proof.Verify() {
		t.Fatal("verified an invalid proof and/or argument")
	}
	proof.Event = event

	// flip every byte in the event
	for i := range proof.Event {
		proof.Event[i] ^= 0x40
		if proof.Verify() {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Event[i] ^= 0x40
	}

	// flip every byte in the event
	for i := range proof.Root {
		proof.Root[i] ^= 0x40
		if proof.Verify() {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Root[i] ^= 0x40
	}

	// for each node in the history tree proof
	for i := range proof.Nodes {
		// flip each byte in the hash of the node
		for j := range proof.Nodes[i].Hash {
			proof.Nodes[i].Hash[j] ^= 0x40
			if proof.Verify() {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.Nodes[i].Hash[j] ^= 0x40
		}

		// flip index in position
		proof.Nodes[i].Position.Index++
		if proof.Verify() {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Nodes[i].Position.Index--

		// flip layer in position
		proof.Nodes[i].Position.Layer++
		if proof.Verify() {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Nodes[i].Position.Layer--
	}
}

func TestQueryUpdate(t *testing.T) {
	// create a tree of size
	size := 128
	tree := NewTree()
	events := make([][]byte, size)
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}
	if tree.Root() == nil {
		t.Fatal("got empty root for non-empty root")
	}

	// create a membership proof for the last inserted event
	proof, err := tree.MembershipProof(size-1, size-1)
	if err != nil {
		t.Fatal("failed to create membership proof")
	}
	if !proof.Verify() {
		t.Fatalf("failed to verify membership proof")
	}

	updateRoot, version, err := proof.Update(events)
	if err != nil {
		t.Fatalf("failed to perform an update based on query: %s", err)
	}
	if version != 2*len(events)-1 {
		t.Fatalf("got wrong version, expected %d, got %d", 2*len(events)-1, version)
	}

	// calculate "real" root
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}
	if !bytes.Equal(tree.Root(), updateRoot) {
		t.Fatal("update root differs from real root")
	}
}

func TestFlipQueryProof(t *testing.T) {
	// create a tree and a valid proof to test
	size := 128
	tree := NewTree()
	events := make([][]byte, size)
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}
	proof, err := tree.MembershipProof(size-1, size-1)
	if err != nil {
		t.Fatalf("failed to create a membership proof: %s", err)
	}
	if !proof.Verify() {
		t.Fatalf("failed to verify membership proof")
	}
}

func TestClone(t *testing.T) {
	// create a tree
	size := 128
	tree := NewTree()
	events := make([][]byte, size)
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}

	// create a clone
	clone := tree.Clone()
	if !util.Equal(clone.Root(), tree.Root()) {
		t.Fatal("expected equal roots")
	}

	// update original tree
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := tree.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}
	if util.Equal(clone.Root(), tree.Root()) {
		t.Fatal("expected different roots")
	}

	// update clone
	for i := 0; i < size; i++ {
		events[i] = []byte("event " + string(i))
		_, err := clone.Add(events[i])
		if err != nil {
			t.Fatalf("failed to add event: %s", err)
		}
	}
	if !util.Equal(clone.Root(), tree.Root()) {
		t.Fatal("expected equal roots")
	}
}
