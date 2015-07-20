/*
Package hashtreap implements a hash treap. A hash treap is a treap that is
authenticated by having the nodes of the tree  form a hash (Merkle) tree.
This implementation is based on a heavily modified immutable treap implementation
by https://github.com/steveyen, available at https://github.com/steveyen/gtreap
under the MIT license. My work is available under the Apache 2 license, see the
LICENSE and README.md files for further details.
*/
package hashtreap

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"sync"

	"github.com/pylls/balloon/util"
)

// NoNodeHash represents the hash of a node that does not exist. Having a hash for
// a non-existent node encodes the structure of the treap into the root hash, which
// is crucial for security (if nothing else enforces structure).
var NoNodeHash []byte

func init() {
	// set NoNodeHash to an all zero slice of the same length as the hash output.
	NoNodeHash = make([]byte, util.HashOutputLen)
	for i := 0; i < util.HashOutputLen; i++ {
		NoNodeHash[i] = 0x00
	}
}

// HashTreap is a treap authenticated by building a hash (Merkle) tree.
type HashTreap struct {
	root *node
	size int
}

type node struct {
	key      []byte
	value    []byte
	priority []byte
	left     *node
	right    *node
	taint    bool
	hash     []byte
}

// QueryProof is a proof proving the correctness of a query.
type QueryProof struct {
	Nodes      []ProofNode
	Key, Value []byte
}

// ProofNode is a node in a proof.
type ProofNode struct {
	Key, Value, Hash []byte
}

// PruneProof is a list of nodes as a reply to a pruned query.
type PruneProof struct {
	Key   []byte
	Nodes []ProofNode
}

// NewHashTreap cretes a new hash treap.
func NewHashTreap() *HashTreap {
	return &HashTreap{root: nil, size: 0}
}

// Size returns the number of nodes in the hash treap.
func (t *HashTreap) Size() int {
	return t.size
}

// Size returns the size in bytes of the query proof.
func (p *QueryProof) Size() (bytes int) {
	bytes = len(p.Key) + len(p.Value)
	for i := 0; i < len(p.Nodes); i++ {
		bytes += len(p.Nodes[i].Hash) + len(p.Nodes[i].Key) + len(p.Nodes[i].Value)
	}
	return
}

// Size returns the size in bytes of the prune proof.
func (p *PruneProof) Size() (bytes int) {
	bytes = len(p.Key)
	for i := 0; i < len(p.Nodes); i++ {
		bytes += len(p.Nodes[i].Hash) + len(p.Nodes[i].Key) + len(p.Nodes[i].Value)
	}
	return
}

// Get returns the value of a target node with the provided key,
// or nil if no node with the target key exists.
func (t *HashTreap) Get(target []byte) []byte {
	n := t.root
	for n != nil {
		c := bytes.Compare(target, n.key)
		if c < 0 {
			n = n.left
		} else if c > 0 {
			n = n.right
		} else {
			return n.value
		}
	}
	return nil
}

// Add attempts to adds a new node with the provided key and value, and returns
// the new hash treap or an error if a node with the provided key already exists.
// Note that the hash of the root of the hash treap is not updated without calling
// Update() or Roots() on the hash treap.
func (t *HashTreap) Add(key, value []byte) (*HashTreap, error) {
	if len(key) == 0 || len(value) == 0 {
		return nil, errors.New("both key and value have to have length over 0")
	}
	if t.Get(key) != nil {
		return nil, errors.New("there is already a node with the provided key")
	}

	nextHashTreap := t.upsert(key, value)
	return nextHashTreap, nil
}

func (t *HashTreap) upsert(key, value []byte) *HashTreap {
	r := t.union(t.root, &node{
		key:      key,
		value:    value,
		priority: util.Hash(key),
		taint:    true,
	})
	return &HashTreap{root: r, size: t.Size() + 1}
}

func (t *HashTreap) union(this *node, that *node) *node {
	if this == nil {
		return that
	}
	if that == nil {
		return this
	}
	// if this.priority > that.priority
	if bytes.Compare(this.priority, that.priority) > 0 {
		left, middle, right := t.split(that, this.key)
		if middle == nil {
			return &node{
				key:      this.key,
				value:    this.value,
				priority: this.priority,
				left:     t.union(this.left, left),
				right:    t.union(this.right, right),
				taint:    true,
			}
		}
	}
	// We don't use middle because the "that" has precendence.
	left, _, right := t.split(this, that.key)
	return &node{
		key:      that.key,
		value:    that.value,
		priority: that.priority,
		left:     t.union(left, that.left),
		right:    t.union(right, that.right),
		taint:    true,
	}
}

// Splits a treap into two treaps based on a split item "s".
// The result tuple-3 means (left, X, right), where X is either...
// nil - meaning the item s was not in the original treap.
// non-nil - returning the node that had item s.
// The tuple-3's left result treap has items < s,
// and the tuple-3's right result treap has items > s.
func (t *HashTreap) split(n *node, s []byte) (*node, *node, *node) {
	if n == nil {
		return nil, nil, nil
	}
	c := bytes.Compare(s, n.key)
	if c < 0 {
		left, middle, right := t.split(n.left, s)
		return left, middle, &node{
			key:      n.key,
			value:    n.value,
			priority: n.priority,
			left:     right,
			right:    n.right,
			taint:    true,
		}
	}
	left, middle, right := t.split(n.right, s)
	return &node{
		key:      n.key,
		value:    n.value,
		priority: n.priority,
		left:     n.left,
		right:    left,
		taint:    true,
	}, middle, right
}

// Update updates the root hash of the hash treap to cover all nodes
// in the treap.
func (t *HashTreap) Update() {
	if t.root == nil {
		return
	}
	wg := new(sync.WaitGroup)
	if t.root.left != nil {
		wg.Add(1)
		go t.updateWorker(t.root.left, wg)
	}
	if t.root.right != nil {
		wg.Add(1)
		go t.updateWorker(t.root.right, wg)
	}
	wg.Wait()

	left := NoNodeHash
	right := NoNodeHash
	if t.root.left != nil {
		left = t.root.left.hash
	}
	if t.root.right != nil {
		right = t.root.right.hash
	}
	t.root.hash = util.Hash(t.root.key, t.root.value, left, right)
	t.root.taint = false
}

func (t *HashTreap) updateWorker(node *node, done *sync.WaitGroup) {
	t.update(node)
	done.Done()
}

func (t *HashTreap) update(node *node) {
	if node.taint {
		left := NoNodeHash
		right := NoNodeHash
		if node.left != nil {
			t.update(node.left)
			left = node.left.hash
		}
		if node.right != nil {
			t.update(node.right)
			right = node.right.hash
		}

		node.hash = util.Hash(node.key, node.value, left, right)
		node.taint = false
	}
}

// Root returns the root hash of the hash treap that fixes the entire hash trep.
func (t *HashTreap) Root() []byte {
	if t.root == nil {
		return nil
	}
	// never return an outdated root
	if t.root.taint {
		t.Update()
	}

	return t.root.hash
}

// MembershipQuery performs a provable query for the membership of a privded key.
// The proof shows either that the key is not a member of the hash treap (proof.Value is then nil),
// or that the key is a member (proof.Value is then != nil).
// Note that the resulting proof is not an unique representation of the proof. In particular,
// some keys and values that make up proof nodes in the proof can be modified and yet the proof
// is a correct proof of a membership query.
func (t *HashTreap) MembershipQuery(key []byte) (proof QueryProof) {
	proof.Key = key

	// nothing is in an empty tree
	if t.size == 0 {
		return
	}

	// we expect to need 2*log2(n) nodes.
	// We multiply by 2 since we mostly need to store 2 nodes per level for the proof.
	// Since the balance of the tree is probabilistic we start out with 10 slots,
	// then trust the law of large numbers.
	proof.Nodes = make([]ProofNode, 0, 10+2*int(math.Log2(float64(t.size))))
	proof.Nodes = append(proof.Nodes, ProofNode{
		Key:   t.root.key,
		Value: t.root.value,
		Hash:  t.root.hash,
	})

	n := t.root
	for n != nil {
		// add children nodes
		if n.left != nil {
			proof.Nodes = append(proof.Nodes, ProofNode{
				Key:   n.left.key,
				Value: n.left.value,
				Hash:  n.left.hash,
			})
		}
		if n.right != nil {
			proof.Nodes = append(proof.Nodes, ProofNode{
				Key:   n.right.key,
				Value: n.right.value,
				Hash:  n.right.hash,
			})
		}

		c := bytes.Compare(key, n.key)
		if c < 0 {
			n = n.left
		} else if c > 0 {
			n = n.right
		} else {
			// member, include the value
			proof.Value = n.value
			return
		}
	}

	// non-member
	return
}

// Verify verifies a membership query for a provided key from an expected
// root hash that fixes a hash treap. Returns true if the proof is valid ,
// false otherwise.
func (p *QueryProof) Verify(key, root []byte) (valid bool) {
	if len(p.Nodes) == 0 {
		// an empty hash treap shows non-membership for any key
		return p.Value == nil && root == nil
	} else if !util.Equal(p.Nodes[0].Hash, root) {
		return false
	}

	// build a pruned
	proofTree := NewHashTreap()
	proofTree.newPrunedHashTreap(p.Nodes)
	value, valid := proofTree.verifiablyGet(key)

	return valid && util.Equal(value, p.Value) && util.Equal(key, p.Key)
}

func (t *HashTreap) verifiablyGet(key []byte) (value []byte, valid bool) {
	n := t.root
	for n != nil {
		// verify the node we are at
		var left, right []byte
		left = NoNodeHash
		right = NoNodeHash
		if n.left != nil {
			left = n.left.hash
		}
		if n.right != nil {
			right = n.right.hash
		}
		// verify the hash
		if !util.Equal(n.hash, util.Hash(n.key, n.value, left, right)) {
			return nil, false
		}

		c := bytes.Compare(key, n.key)
		if c < 0 {
			n = n.left
		} else if c > 0 {
			n = n.right
		} else {
			return n.value, true
		}
	}
	return nil, true
}

// newPrunedHashTreap builds a pruned hash treap based on a proof containing an
// authenticated path. It is assumed that the nodes in the proof are in
// the order they were traversed (binary search from the root). Duplicate
// nodes are OK.
func (t *HashTreap) newPrunedHashTreap(nodes []ProofNode) {
	t.root = t.addProofNode(t.root, &nodes[0])
	for i := 1; i < len(nodes); i++ {
		t.addProofNode(t.root, &nodes[i])
	}
}

func (t *HashTreap) addProofNode(n *node, proofNode *ProofNode) *node {
	if n == nil {
		t.size++
		return &node{
			key:      proofNode.Key,
			value:    proofNode.Value,
			hash:     proofNode.Hash,
			priority: util.Hash(proofNode.Key),
			taint:    false,
		}
	}

	c := bytes.Compare(proofNode.Key, n.key)
	if c < 0 {
		n.left = t.addProofNode(n.left, proofNode)
	} else if c > 0 {
		n.right = t.addProofNode(n.right, proofNode)
	}

	return n
}

// QueryPrune performs a prune query in the hash treap for a set of keys. The minimalProof flag
// removes redundant nodes in the proof, greatly reducing proof size for large sets of keys.
// Returns true if the keys can be used to update the Balloon, otherwise false. The proof proofs
// the reply.
func (t *HashTreap) QueryPrune(keys [][]byte, minimalProof bool) (answer bool, proof PruneProof) {
	answer = true // no keys is always OK

	// we only have to include nodes if there are any keys to query for
	// and the tree has any nodes
	if len(keys) > 0 && t.size > 0 {
		proof.Nodes = make([]ProofNode, 0, len(keys)*(10+2*int(math.Log2(float64(t.size)))))
		// add root
		proof.Nodes = append(proof.Nodes, ProofNode{
			Key:   t.root.key,
			Value: t.root.value,
			Hash:  t.root.hash,
		})

		// the goal below is to do a membership query for all keys in parallel
		wg := new(sync.WaitGroup)
		keyChan := make(chan []byte, len(keys))
		proofChan := make(chan QueryProof, len(keys))

		// one worker per core
		for i := 0; i < runtime.NumCPU(); i++ {
			wg.Add(1)
			go t.pruneWorker(keyChan, proofChan, wg)
		}

		// send keys to workers
		for _, k := range keys {
			keyChan <- k
		}

		// no more keys to send, stops worker from waiting
		close(keyChan)

		// wait for the workers to finish
		wg.Wait()

		// no more proofs to be generated
		close(proofChan)

		// put together the proof
		for p := range proofChan {
			// if a proof proves member, return false and replace the proof
			if p.Value != nil {
				proof.Nodes = p.Nodes
				proof.Key = p.Key
				return false, proof
			}
			proof.Nodes = append(proof.Nodes, p.Nodes...)
		}

		// optional: remove duplicate nodes in the proof,
		// trades computation for reduced proof size
		if minimalProof {
			unique := make(map[string]bool)

			for i := 0; i < len(proof.Nodes); i++ {
				if _, seen := unique[string(proof.Nodes[i].Key)]; !seen {
					proof.Nodes[len(unique)] = proof.Nodes[i]
					unique[string(proof.Nodes[i].Key)] = true
				}
			}
			proof.Nodes = proof.Nodes[:len(unique)]
		}

	}

	return
}

func (t *HashTreap) pruneWorker(keyChan chan []byte, proofChan chan QueryProof,
	wg *sync.WaitGroup) {
	defer wg.Done()

	for key := range keyChan {
		proofChan <- t.MembershipQuery(key)
	}
}

// Verify verifies a prune proof for the provided arguments. Returns true if valid,
// otherwise false.
func (p *PruneProof) Verify(keys [][]byte, answer bool, root []byte) (valid bool) {
	// always possible to insert no keys
	if len(keys) == 0 {
		return answer // same as answer == true
	}

	// create a pruned hash treap out of all nodes in the proof
	proofTree := NewHashTreap()
	if len(p.Nodes) > 0 {
		// linearly build the proof tree
		// this involves no verification of the nodes
		proofTree.newPrunedHashTreap(p.Nodes)
	}

	if !util.Equal(root, proofTree.Root()) {
		return false
	}

	// go over each key, looking if it exists in the proof
	for _, k := range keys {
		value, valid := proofTree.verifiablyGet(k)
		// at least one invalid node in the proof
		if !valid {
			return false
		}
		// the key exists
		if value != nil {
			return !answer && util.Equal(k, p.Key)
		}
	}

	return answer
}

// Update creates for a valid PruneProof, with the same keys and answer true,
// the resulting root of updating the hash treap the PruneProof was created from
// when adding the provided keys and values. Returns the updated root, or an error
// if the update fails.
func (p *PruneProof) Update(keys, values [][]byte) (root []byte, err error) {
	// create a pruned hash treap out of all nodes in the proof
	proofTree := NewHashTreap()
	if len(p.Nodes) > 0 {
		proofTree.newPrunedHashTreap(p.Nodes)
	}

	// add each key
	for i := 0; i < len(keys); i++ {
		proofTree, err = proofTree.Add(keys[i], values[i])
		if err != nil {
			return
		}
	}
	proofTree.Update()

	return proofTree.Root(), nil
}
