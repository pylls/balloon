/*
Package balloon implements Balloon, an authenticated data structure that is
based on a hash treap and a history tree. The design is available
at https://eprint.iacr.org/2015/007 .

This is a proof-of-concept implementation and should not be used for anything serious.
*/
package balloon

import (
	"bytes"
	"errors"
	"sort"

	"github.com/pylls/balloon/hashtreap"
	"github.com/pylls/balloon/historytree"
	"github.com/pylls/balloon/util"
)

// Balloon is a balloon.
type Balloon struct {
	treap          *hashtreap.HashTreap
	history        *historytree.Tree
	events         EventStorage
	sk, vk         []byte
	latestsnapshot Snapshot
	latesteventkey []byte
}

// Event is an event that gets inserted into a balloon.
type Event struct {
	Key, Value []byte
}

// Snapshot fixes the entire Balloon at the time of snapshot creation.
type Snapshot struct {
	Roots     Roots
	Signature []byte
	Index     int
	Previous  []byte
}

// EventStorage specifies the interface for how to store and lookup events.
type EventStorage interface {
	// Store stores a set of events and the generated snapshot as a result of
	// storing the events in Balloon.
	Store(events []Event, snap Snapshot) (err error)
	// LookupEvent returns the event, if it exists, with the provided key.
	LookupEvent(key []byte) (event *Event, err error)
	// Clone creates a copy of the EventStorage.
	Clone() (clone EventStorage)
}

// QueryProof is a proof of a membership query.
type QueryProof struct {
	TreapProof   hashtreap.QueryProof
	HistoryProof historytree.MembershipProof
}

// PruneProof is a proof of a prune query.
type PruneProof struct {
	Event      Event
	TreapProof hashtreap.PruneProof
	QueryProof QueryProof
}

// Roots contain the roots of the hash treap and history tree, together with
// the version of the history tree.
type Roots struct {
	Version        int
	Treap, History []byte
}

// ByKey is a type used for sorting events.
type ByKey []Event

// Len returns the length of the events being sorted.
func (a ByKey) Len() int { return len(a) }

// Swap swaps two events being sorted by key.
func (a ByKey) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less returns true if the event with index i is less than the event with index j
func (a ByKey) Less(i, j int) bool { return bytes.Compare(a[i].Key, a[j].Key) == -1 }

// NewBalloon returns a new balloon.
func NewBalloon(storage EventStorage) (balloon *Balloon) {
	balloon = new(Balloon)
	balloon.treap = hashtreap.NewHashTreap()
	balloon.history = historytree.NewTree()
	balloon.events = storage
	return
}

// Clone creates a copy of the balloon.
func (balloon *Balloon) Clone() (clone *Balloon) {
	clone = new(Balloon)
	clone.treap = balloon.treap
	clone.history = balloon.history.Clone()
	clone.events = balloon.events.Clone()
	clone.latestsnapshot = balloon.latestsnapshot
	clone.sk = balloon.sk
	clone.vk = balloon.vk
	return
}

// Size returns the number of events in the balloon.
func (balloon *Balloon) Size() int {
	return balloon.history.Size()
}

// Size returns the size, in bytes, of the query proof.
func (proof *QueryProof) Size() (bytes int) {
	return proof.HistoryProof.Size() + proof.TreapProof.Size()
}

// Size returns the size, in bytes, of the prune proof.
func (proof *PruneProof) Size() (bytes int) {
	return len(proof.Event.Key) + len(proof.Event.Value) +
		proof.QueryProof.Size() + proof.TreapProof.Size()
}

// Equal determines if another snapshot is equal to this snapshot.
func (snap *Snapshot) Equal(other *Snapshot) bool {
	if snap == nil || other == nil ||
		snap.Index != other.Index ||
		!util.Equal(snap.Signature, other.Signature) ||
		!util.Equal(snap.Roots.History, other.Roots.History) ||
		!util.Equal(snap.Roots.Treap, other.Roots.Treap) ||
		snap.Roots.Version != other.Roots.Version {
		return false
	}

	return true
}

// Genkey generates a key-pair for balloon. Note that the ordering function
// is hardcoded in this implentation.
func Genkey() (sk, vk []byte, err error) {
	return util.GenerateSigningKeyPair()
}

// Setup creates a new balloon based on the slice of events (may be empty or nil). Returns the
// first snapshot. Run by the author on trusted input.
func Setup(events []Event, sk, vk []byte, storage EventStorage) (balloon *Balloon, snap *Snapshot, err error) {
	balloon = NewBalloon(storage)
	balloon.sk = sk
	balloon.vk = vk

	// do same as update, allow events to be empty
	if len(events) > 0 {
		sort.Sort(ByKey(events))

		// add events
		for i := 0; i < len(events); i++ {
			// add the hash of the entire event to the history tree
			_, err = balloon.history.Add(util.Hash(append(events[i].Key, events[i].Value...)))
			if err != nil {
				return nil, nil, err
			}

			// add to the treap the hash of the key pointing to the index (version) of the
			// hash of the event in the history tree
			balloon.treap, err = balloon.treap.Add(util.Hash(events[i].Key),
				util.Itob(balloon.history.LatestVersion()))
			if err != nil {
				return nil, nil, err
			}
		}
	}

	// create first snapshot
	snap = new(Snapshot)
	snap.Index = 0
	snap.Roots.History = balloon.history.Root()
	snap.Roots.Treap = balloon.treap.Root()
	snap.Roots.Version = balloon.history.LatestVersion()
	snap.Previous = nil

	signature, err := util.Sign(balloon.sk,
		append(append([]byte("snapshot"), snap.Roots.History...), append(snap.Roots.Treap, snap.Previous...)...))
	if err != nil {
		panic(err)
	}
	snap.Signature = signature

	// actually store events
	err = balloon.events.Store(events, *snap)
	if err != nil {
		return nil, nil, err
	}
	balloon.latestsnapshot = *snap
	if len(events) > 0 {
		balloon.latesteventkey = events[len(events)-1].Key
	}

	return
}

// Update updates balloon with the slice of events, producing the next snapshot.
// Run by the author on trusted input.
func (balloon *Balloon) Update(events []Event, current *Snapshot,
	sk []byte) (next *Snapshot, err error) {
	if len(events) == 0 {
		return nil, errors.New("you need to add at least one event")
	}
	if !util.Equal(current.Roots.History, balloon.history.Root()) ||
		!util.Equal(current.Roots.Treap, balloon.treap.Root()) {
		return nil, errors.New("provided snapshot is not current")
	}

	sort.Sort(ByKey(events))

	// attempt to add events
	treap := balloon.treap
	ht := balloon.history.Clone()
	for i := 0; i < len(events); i++ {
		// add the hash of the entire event to the history tree
		_, err = ht.Add(util.Hash(append(events[i].Key, events[i].Value...)))
		if err != nil {
			return
		}

		// add to the treap the hash of the key pointing to the index (version) of the
		// hash of the event in the history tree
		treap, err = treap.Add(util.Hash(events[i].Key), util.Itob(ht.LatestVersion()))
		if err != nil {
			return
		}
	}

	// attempt to create next snapshot
	next = new(Snapshot)
	next.Index = current.Index + 1
	next.Roots.History = ht.Root()
	next.Roots.Treap = treap.Root()
	next.Roots.Version = ht.LatestVersion()
	next.Previous = current.Signature
	signature, err := util.Sign(balloon.sk,
		append(append([]byte("snapshot"), next.Roots.History...), append(next.Roots.Treap, next.Previous...)...))
	if err != nil {
		panic(err)
	}
	next.Signature = signature

	// all is OK, save result
	err = balloon.events.Store(events, *next)
	if err != nil {
		return nil, err
	}
	balloon.latestsnapshot = *next
	if len(events) > 0 {
		balloon.latesteventkey = events[len(events)-1].Key
	}
	balloon.treap = treap
	balloon.history = ht

	return
}

// Refresh updates balloon with the slice of events. Returns an error if the update
// fails to produce a snapshot identical to the provided next one.
// Run by the server on input (events and next) that will be verified.
func (balloon *Balloon) Refresh(events []Event, current, next *Snapshot,
	vk []byte) (err error) {
	// current can be empty on the first run of Refresh
	if current == nil && balloon.Size() > 0 {
		return errors.New("current snapshot required for non-zero Balloon")
	}

	if current != nil {
		if !util.Equal(current.Roots.History, balloon.history.Root()) ||
			!util.Equal(current.Roots.Treap, balloon.treap.Root()) ||
			current.Roots.Version+len(events) != next.Roots.Version {
			return errors.New("provided snapshot is not current")
		}
		if !util.Verify(vk,
			append(append([]byte("snapshot"), current.Roots.History...),
				append(current.Roots.Treap, current.Previous...)...),
			current.Signature) {
			return errors.New("invalid signature in current snapshot")
		}
	}

	treap := balloon.treap
	ht := balloon.history.Clone()
	if len(events) > 0 {
		sort.Sort(ByKey(events))

		// attempt to add events
		for i := 0; i < len(events); i++ {
			// add the hash of the entire event to the history tree
			_, err = ht.Add(util.Hash(append(events[i].Key, events[i].Value...)))
			if err != nil {
				return
			}

			// add to the treap the hash of the key pointing to the index (version) of the
			// hash of the event in the history tree
			treap, err = treap.Add(util.Hash(events[i].Key), util.Itob(ht.LatestVersion()))
			if err != nil {
				return
			}
		}
	}

	var prev []byte
	if current != nil {
		prev = current.Signature
	}

	// compare snapshot with next snapshot
	if !util.Equal(ht.Root(), next.Roots.History) ||
		!util.Equal(treap.Root(), next.Roots.Treap) ||
		ht.LatestVersion() != next.Roots.Version ||
		!util.Equal(prev, next.Previous) {
		return errors.New("roots or version mismatch")
	}

	if current == nil {
		if next.Index != 0 {
			return errors.New("index not what expected in next snapshot")
		}
	} else if current.Index+1 != next.Index {
		return errors.New("index not what expected in next snapshot")
	}

	if !util.Verify(vk,
		append(append([]byte("snapshot"), next.Roots.History...), append(next.Roots.Treap, next.Previous...)...),
		next.Signature) {
		return errors.New("invalid signature")
	}

	// all is OK, store results
	err = balloon.events.Store(events, *next)
	if err != nil {
		return err
	}
	balloon.latestsnapshot = *next
	if len(events) > 0 {
		balloon.latesteventkey = events[len(events)-1].Key
	}
	balloon.treap = treap
	balloon.history = ht

	return
}

// QueryMembership queries for an event with a key in a particular snapshot in the balloon.
// Returns an answer (is member?), an event (if the answer is true), and a proof (always).
// Run by the server with untrusted input (key and queried).
func (balloon *Balloon) QueryMembership(key []byte, queried *Snapshot,
	vk []byte) (answer bool, event *Event, proof QueryProof, err error) {
	answer = false

	// verify the queried snapshot
	if !util.Verify(vk,
		append(append([]byte("snapshot"), queried.Roots.History...),
			append(queried.Roots.Treap, queried.Previous...)...),
		queried.Signature) {
		return answer, nil, proof, errors.New("invalid signature")
	}

	// verify the length of the key
	if len(key) != util.HashOutputLen {
		return answer, nil, proof, errors.New("invalid key length")
	}

	// check hash treap for hash of key
	proof.TreapProof = balloon.treap.MembershipQuery(util.Hash(key))

	// if not in treap, then a non-membership is done
	if proof.TreapProof.Value == nil {
		return
	}

	// the position (index) of the event in the history tree
	index := util.Btoi(proof.TreapProof.Value)

	// was the event added _after_ the queried for snapshot was created?
	if index > queried.Roots.Version {
		return
	}

	// ok, now we know it's a membership proof, so we query the history tree
	proof.HistoryProof, err = balloon.history.MembershipProof(index, queried.Roots.Version)
	if err != nil {
		panic(err)
	}

	// get the event from storage
	e, err := balloon.events.LookupEvent(key)
	if err != nil {
		return
	}

	return true, e, proof, nil
}

// Verify verifies a proof and answer from QueryMembership. Returns true if the
// answer and proof are correct and consistent, otherwise false.
// Run by a client on input that should be verified.
func (proof *QueryProof) Verify(key []byte, queried, current *Snapshot,
	answer bool, event *Event, vk []byte) (valid bool) {

	// verify the snapshots
	if !util.Verify(vk,
		append(append([]byte("snapshot"), queried.Roots.History...),
			append(queried.Roots.Treap, queried.Previous...)...),
		queried.Signature) {
		return false
	}
	if !util.Verify(vk,
		append(append([]byte("snapshot"), current.Roots.History...),
			append(current.Roots.Treap, current.Previous...)...),
		current.Signature) {
		return false
	}

	// check the authenticated path in the hash treap
	if !proof.TreapProof.Verify(util.Hash(key), current.Roots.Treap) {
		return false
	}

	// a non-membership proof where there is no event in the treap
	if !answer && proof.TreapProof.Value == nil && event == nil {
		return true
	}

	// a non-membership proof where the event was added _after_ the queried for snapshot
	index := util.Btoi(proof.TreapProof.Value)
	if !answer && index > queried.Roots.Version {
		return true
	}

	// a membership proof
	if answer && event != nil && util.Equal(event.Key, key) && proof.HistoryProof.Verify() &&
		proof.HistoryProof.Index == index && proof.HistoryProof.Version == queried.Roots.Version &&
		util.Equal(proof.HistoryProof.Root, queried.Roots.History) &&
		util.Equal(proof.HistoryProof.Event, util.Hash(event.Key, event.Value)) {
		return true
	}

	// otherwise the proof is invalid
	return false
}

// QueryPrune performs a prune query for a slice of events. Returns an answer indicating
// if the events can be added and a proof.
// Run by the server on untrusted input. The minimalProof flag trades a small amount
// of computation for a significantly smaller proof (the more events, the bigger the reduction).
func (balloon *Balloon) QueryPrune(events []Event, vk []byte,
	minimalProof bool) (answer bool, proof PruneProof) {
	// query hash treap
	treapKeys := make([][]byte, len(events))
	for i := 0; i < len(events); i++ {
		treapKeys[i] = util.Hash(events[i].Key)
	}
	answer, proof.TreapProof = balloon.treap.QueryPrune(treapKeys, minimalProof)

	// if we found a member among the keys, then the proof is done shows that it is not
	// posssible to insert the set of events
	if !answer {
		return
	}

	// we only need/can extract the latest event, whose membership query fixes the history
	// tree, if there is at least one event in the Balloon
	if balloon.Size() > 0 {
		members, qevent, qproof, err := balloon.QueryMembership(balloon.latesteventkey,
			&balloon.latestsnapshot, vk)
		if err != nil {
			panic(err)
		}
		if !members {
			panic("an event that should be a member is not")
		}
		if !util.Equal(balloon.latesteventkey, qevent.Key) {
			panic("events differ")
		}
		proof.QueryProof = qproof
		proof.Event = *qevent
	}

	return
}

// Verify verifies a proof and answer from QueryPrune. Returns true if the answer
// and proof is correct, otherwise false. Run by the author.
func (proof *PruneProof) Verify(events []Event, answer bool, current *Snapshot,
	vk []byte) (valid bool) {
	valid = true

	if !util.Verify(vk,
		append(append([]byte("snapshot"), current.Roots.History...),
			append(current.Roots.Treap, current.Previous...)...),
		current.Signature) {
		return false
	}

	// always possible to add no events
	if len(events) == 0 {
		return answer // same as answer == true
	}

	// verify the prune proof in the hash treap
	treapKeys := make([][]byte, len(events))
	for i := 0; i < len(events); i++ {
		treapKeys[i] = util.Hash(events[i].Key)
	}
	valid = proof.TreapProof.Verify(treapKeys, answer, current.Roots.Treap)
	if !valid {
		return
	}

	// check the query if needed
	if answer {
		valid = proof.QueryProof.Verify(proof.Event.Key, current, current, true, &proof.Event, vk)
	}

	return valid
}

// Update creates the next snapshot from adding the provided events in the balloon
// fixed by the current snapshot. This function depends on that the provided prune proof has
// been successfully verified for the answer true.
// Run by the author on input that should have been verified before by using Verify.
func (proof *PruneProof) Update(events []Event, current *Snapshot,
	sk []byte) (next *Snapshot, err error) {

	sort.Sort(ByKey(events))

	// calculate balloon internal keys and values based on events
	startIndex := proof.QueryProof.HistoryProof.Index + 1
	values := make([][]byte, len(events))
	treapKeys := make([][]byte, len(events))
	treapValues := make([][]byte, len(events))
	for i := 0; i < len(events); i++ {
		values[i] = util.Hash(append(events[i].Key, events[i].Value...))
		treapKeys[i] = util.Hash(events[i].Key)
		treapValues[i] = util.Itob(startIndex + i)
	}

	// calculate updated commitment on the history tree
	c, version, err := proof.QueryProof.HistoryProof.Update(values)
	if err != nil {
		return nil, err
	}

	// calculate updated hash treap root
	root, err := proof.TreapProof.Update(treapKeys, treapValues)
	if err != nil {
		return nil, err
	}

	next = new(Snapshot)
	next.Roots.History = c
	next.Roots.Treap = root
	next.Roots.Version = version
	next.Previous = current.Signature
	signature, err := util.Sign(sk,
		append(append([]byte("snapshot"), next.Roots.History...),
			append(next.Roots.Treap, next.Previous...)...))
	if err != nil {
		panic(err)
	}
	next.Signature = signature

	return
}

// RefreshVerify attempts to refresh the balloon with the provided events and compares
// the resulting balloon with that fixed by the next snapshot. Returns true if valid,
// otherwise false.
// Run by the server, monitor, or auditor on input that will be verified.
func (balloon *Balloon) RefreshVerify(events []Event, current, next *Snapshot,
	vk []byte) (answer bool) {

	// Refresh is as strict as RefreshVerify, unlike how Refresh is specified in
	// the Balloon paper. We made this change because in practise the server (running
	// the Refresh algorithm) will always want to verify the snapshots provided by
	// the author and that they are consistent with the provided events.
	return balloon.Refresh(events, current, next, vk) == nil
}
