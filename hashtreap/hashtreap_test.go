package hashtreap

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"testing"

	"github.com/pylls/balloon/util"
)

func TestAdd(t *testing.T) {
	value := util.Itob(42)
	tree := NewHashTreap()

	k0 := util.Itob(0) // priority 1b7409ccf0d5a34d3a77eaabfa9fe27427655be9297127ee9522aa1bf4046d4f
	t.Logf("priority of k0 is %s", hex.EncodeToString(util.Hash(k0)))
	k1 := util.Itob(1) // priority aa826d9d5f563309b4a9043987ff0d87e82d32d2ddc813aab7defe15f9062911
	t.Logf("priority of k1 is %s", hex.EncodeToString(util.Hash(k1)))
	k2 := util.Itob(2) // priority 8c7471bddfd31fa1e83a761a2f5bc2fc772a5567c85b3a753d3b8a2e8259386f
	t.Logf("priority of k2 is %s", hex.EncodeToString(util.Hash(k2)))
	k3 := util.Itob(3) // priority f6ec9d10ae03d32f6b31ae37322b629ec7caad83dd3c5dd870df8e6fd13a5a51
	t.Logf("priority of k3 is %s", hex.EncodeToString(util.Hash(k3)))
	k4 := util.Itob(4) // priority 2a364b052431533577431129ac1acce106dd019245de82ad97663290b5dbb9cc
	t.Logf("priority of k4 is %s", hex.EncodeToString(util.Hash(k4)))

	tree.Update()
	if tree.Root() != nil {
		t.Fatal("empty tree returned non-nil root")
	}

	tree, err := tree.Add(k0, value)
	if err != nil {
		t.Fatalf("failed to add key in empty tree: %s", err)
	}
	// should be that root == H(k0||value||NoNodeHash||NoNodeHash)
	if !bytes.Equal(tree.Root(), util.Hash(k0, value, NoNodeHash, NoNodeHash)) {
		t.Fatalf("the root of the tree of size %d is invalid", tree.Size())
	}

	tree, err = tree.Add(k1, value)
	if err != nil {
		t.Fatalf("failed to add key in tree of length %d: %s", tree.Size(), err)
	}
	tree.Update()
	// k1 > k0, and k0 has a smaller priority than k1, so the tree is:
	//      k1
	//     /
	//   k0
	// it should be that root = H(k1||value|| H(k0||value||NoNodeHash||NoNodeHash)|| NoNodeHash)
	if !bytes.Equal(tree.Root(), util.Hash(k1, value,
		util.Hash(k0, value, NoNodeHash, NoNodeHash), NoNodeHash)) {
		t.Fatalf("the root of the tree of size %d is invalid", tree.Size())
	}

	tree, err = tree.Add(k2, value)
	if err != nil {
		t.Fatalf("failed to add key in tree of length %d: %s", tree.Size(), err)
	}
	tree.Update()
	// k2 > k1 > k0, and priority is k1 > k2 > k0, so the tree is:
	//      k1
	//     /  \
	//   k0    k2
	// it should be that root = H(k1||value||
	//                          H(k0||value||NoNodeHash||NoNodeHash)||
	// 							H(k2||value||NoNodeHash||NoNodeHash))
	if !bytes.Equal(tree.Root(), util.Hash(k1, value,
		util.Hash(k0, value, NoNodeHash, NoNodeHash),
		util.Hash(k2, value, NoNodeHash, NoNodeHash))) {
		t.Fatalf("the root of the tree of size %d is invalid", tree.Size())
	}

	tree, err = tree.Add(k3, value)
	if err != nil {
		t.Fatalf("failed to add key in tree of length %d: %s", tree.Size(), err)
	}
	tree.Update()
	// k3 > k2 > k1 > k0, and priority is k3 > k1 > k2 > k0, so the tree is:
	//         k3
	//        /
	//      k1
	//     /  \
	//   k0    k2
	// it should be that root = H(k3||value||
	//                          H(k1||value||
	//                          H(k0||value||NoNodeHash||NoNodeHash)||
	// 							H(k2||value||NoNodeHash||NoNodeHash))||
	//                          NoNodeHash)
	if !bytes.Equal(tree.Root(), util.Hash(k3, value, util.Hash(k1, value,
		util.Hash(k0, value, NoNodeHash, NoNodeHash),
		util.Hash(k2, value, NoNodeHash, NoNodeHash)),
		NoNodeHash)) {
		t.Fatalf("the root of the tree of size %d is invalid", tree.Size())
	}

	tree, err = tree.Add(k4, value)
	if err != nil {
		t.Fatalf("failed to add key in tree of length %d: %s", tree.Size(), err)
	}
	tree.Update()
	// k4 > k3 > k2 > k1 > k0, and priority is k3 > k1 > k2 > k4 > k0, so the tree is:
	//         k3
	//        /  \
	//      k1    k4
	//     /  \
	//   k0    k2
	// it should be that root = H(k3||value||
	//                          H(k1||value||
	//                          H(k0||value||NoNodeHash||NoNodeHash)||
	// 							H(k2||value||NoNodeHash||NoNodeHash))||
	//                          H(k4||value||NoNodeHash||NoNodeHash))
	if !bytes.Equal(tree.Root(), util.Hash(k3, value, util.Hash(k1, value,
		util.Hash(k0, value, NoNodeHash, NoNodeHash),
		util.Hash(k2, value, NoNodeHash, NoNodeHash)),
		util.Hash(k4, value, NoNodeHash, NoNodeHash))) {
		t.Fatalf("the root of the tree of size %d is invalid", tree.Size())
	}

	_, err = tree.Add(nil, nil)
	if err == nil {
		t.Fatal("added (nil,nil) without an error")
	}
	_, err = tree.Add(k4, value)
	if err == nil {
		t.Fatal("successfully added a node with the same key twice")
	}

	if tree.Get([]byte("a key not there")) != nil {
		t.Fatal("got value for key not in the hash treap")
	}
}

func TestMembershipQuery(t *testing.T) {
	keys := 1024
	treap := NewHashTreap()

	// test in an empty hash treap
	proof := treap.MembershipQuery(util.Itob(keys + 42))
	if proof.Value != nil {
		t.Fatalf("a membership query for a non-member key %d returned a non-membership proof", keys+42)
	}
	if !proof.Verify(util.Itob(keys+42), treap.Root()) {
		t.Fatalf("failed to verify a membership query proof for key %d that was just added", keys+42)
	}

	// create a hash treap with a static number of keys in a random permutation
	// (note that a hash treap is set unique so the same hash treap is always tested)
	ints := mrand.Perm(keys)
	var err error
	for i := 0; i < len(ints); i++ {
		treap, err = treap.Add(util.Itob(i), util.Itob(i))
		if err != nil {
			t.Fatalf("failed to add to hash treap: %s", err)
		}
	}
	treap.Update()

	// test queries proving membership
	for _, i := range ints {
		proof := treap.MembershipQuery(util.Itob(i))
		if proof.Value == nil {
			t.Fatalf("a membership query for member key %d returned a non-membership proof", i)
		}
		if !proof.Verify(util.Itob(i), treap.Root()) {
			t.Fatalf("failed to verify a membership query proof for key %d that was just added", i)
		}
	}

	// test queries proving non-membership
	for i := keys; i < 2*keys; i++ {
		proof := treap.MembershipQuery(util.Itob(i))
		if proof.Value != nil {
			t.Fatalf("got a membership proof for a non-member key %d", i)
		}
		if !proof.Verify(util.Itob(i), treap.Root()) {
			t.Fatalf("failed to verify a non-membership query proof for a key %d that is not a member", i)
		}
		if proof.Size() <= 0 {
			t.Fatal("size of proof too small")
		}
	}

	// test bit-flips in queries proving membership
	for i := 0; i < 4; i++ {
		proof := treap.MembershipQuery(util.Itob(ints[i]))
		root := make([]byte, len(treap.Root()))
		copy(root, treap.Root())

		// flip every byte in the proof key
		for j := range proof.Key {
			proof.Key[j] ^= 0x40
			if proof.Verify(util.Itob(ints[i]), root) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.Key[j] ^= 0x40
		}

		// flip every byte in the proof value
		for j := range proof.Value {
			proof.Value[j] ^= 0x40
			if proof.Verify(util.Itob(ints[i]), root) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.Value[j] ^= 0x40
		}

		// for each node in the hash treap proof
		for j := range proof.Nodes {
			// flip every byte in the hash of the node
			for k := range proof.Nodes[j].Hash {
				proof.Nodes[j].Hash[k] ^= 0x40
				if proof.Verify(util.Itob(ints[i]), root) {
					t.Fatal("verified an invalid proof and/or argument")
				}
				proof.Nodes[j].Hash[k] ^= 0x40
			}

			// Note that we _cannot_ detect flips in a proof node's key and value when
			// the node's key and value are only used to place the node's hash either
			// left or right along the verified authenticated path in the hash treap.
			// This is not an issue for the security of a membership query.
		}
	}
}

func TestPruneQuery(t *testing.T) {
	count := 1024
	treap := NewHashTreap()
	ints := mrand.Perm(count)
	var err error
	for i := 0; i < len(ints); i++ {
		treap, err = treap.Add(util.Itob(i), util.Itob(i))
		if err != nil {
			t.Fatalf("failed to add to hash treap: %s", err)
		}
	}
	treap.Update()

	// size new random events
	size := 42
	keys := make([][]byte, size)
	values := make([][]byte, size)
	for i := 0; i < size; i++ {
		keys[i] = make([]byte, util.HashOutputLen)
		_, err := rand.Read(keys[i])
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		values[i] = util.Hash(keys[i])
	}

	// query for new events
	possible, proof := treap.QueryPrune(keys, true)
	if !possible {
		t.Fatal("not possible to add random keys, highly unlikely")
	}
	if !proof.Verify(keys, possible, treap.Root()) {
		t.Fatal("failed to verify valid proof")
	}
	if proof.Size() <= 0 {
		t.Fatal("size of proof too small")
	}

	root, err := proof.Update(keys, values)
	if err != nil {
		t.Fatalf("failed to calculate an updated root from a pruned proof: %s", err)
	}

	// calculate root to compare with
	for i := 0; i < len(keys); i++ {
		treap, err = treap.Add(keys[i], values[i])
		if err != nil {
			t.Fatalf("failed to add to hash treap: %s", err)
		}
	}
	treap.Update()
	if !bytes.Equal(treap.Root(), root) {
		t.Fatal("pruned root and actual root differs")
	}

	// test when the prune query should prove that it is not possible
	possible, proof = treap.QueryPrune(keys, true)
	if possible {
		t.Fatal("possible to add key that was just added")
	}
	if !proof.Verify(keys, possible, treap.Root()) {
		t.Fatal("failed to verify valid proof")
	}
	if proof.Size() <= 0 {
		t.Fatal("size of proof too small")
	}
	// ignore what the proof said, try to update
	_, err = proof.Update(keys, values)
	if err == nil {
		t.Fatal("managed to calculate updated root when adding key already in place")
	}
	// all proofs show that we can add no keys
	if !proof.Verify(nil, true, treap.Root()) {
		t.Fatal("failed to verify valid proof")
	}

	// flip every byte in the key of the proof
	for i := range proof.Key {
		proof.Key[i] ^= 0x40
		if proof.Verify(keys, possible, treap.Root()) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Key[i] ^= 0x40
	}

	// treap.Root() and the hash in the first proof node point to the same slice,
	// so we need to make a copy, otherwise we change both...
	root = make([]byte, len(treap.Root()))
	copy(root, treap.Root())
	for i := range proof.Nodes {
		// flip every byte in the hash of the node
		for j := range proof.Nodes[i].Hash {
			proof.Nodes[i].Hash[j] ^= 0x40
			if proof.Verify(keys, possible, root) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.Nodes[i].Hash[j] ^= 0x40
		}
	}
}
