package balloon

import (
	"crypto/rand"
	"errors"
	"strconv"
	"testing"

	"github.com/mndrix/ps"
	"github.com/pylls/balloon/util"
)

type TestEventStorage struct {
	events    ps.Map
	snapshots ps.Map
}

func NewTestEventStorage() TestEventStorage {
	var storage TestEventStorage
	storage.events = ps.NewMap()
	storage.snapshots = ps.NewMap()
	return storage
}

func (storage TestEventStorage) Store(events map[int]Event,
	snap Snapshot) (next EventStorage, err error) {
	e := storage.events
	s := storage.snapshots
	for version, event := range events {
		e = e.Set(strconv.Itoa(version), event)
	}
	s = s.Set(strconv.Itoa(snap.Index), snap)

	return TestEventStorage{events: e, snapshots: s}, nil
}

func (storage TestEventStorage) LookupEvent(version int) (event *Event,
	err error) {
	e, exists := storage.events.Lookup(strconv.Itoa(version))
	if !exists {
		return nil, errors.New("no such event")
	}
	var result Event
	result.Key = (e.(Event)).Key
	result.Value = (e.(Event)).Value

	return &result, nil
}

func TestBalloon(t *testing.T) {
	/*
		Basics
	*/

	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}

	// setup for an initially empty Balloon for the author
	author, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}

	// update the Balloon with some events
	size := 10
	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	s1, err := author.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}

	// for the server, create an empty balloon
	server := NewBalloon(NewTestEventStorage())

	// refresh with the initial empty events
	err = server.Refresh(nil, nil, s0, vk)
	if err != nil {
		t.Fatalf("failed to do initial refresh: %s", err)
	}

	// refresh with events
	err = server.Refresh(events, s0, s1, vk)
	if err != nil {
		t.Fatalf("failed to do refresh from s0 to s1: %s", err)
	}

	// create some more events, update, and refresh
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	s2, err := author.Update(events[:1], s1, sk)
	if err != nil {
		t.Fatalf("failed to update to 2: %s", err)
	}
	// refresh with events
	err = server.Refresh(events[:1], s1, s2, vk)
	if err != nil {
		t.Fatalf("failed to do refresh from s1 to s2: %s", err)
	}

	/*
		Membership queries
	*/

	// check if the event we just inserted into the Balloon exists in the latest snapshot
	answer, event, proof, err := server.QueryMembership(events[0].Key, s2, vk)
	if err != nil {
		t.Fatalf("failed to perform a membership query: %s", err)
	}
	if !answer {
		t.Fatal("got a false answer for a membership query that should have answered true")
	}
	if event == nil {
		t.Fatal("got an empty event for a membership query that should have returned an event")
	}
	if !proof.Verify(events[0].Key, s2, s2, answer, event, vk) {
		t.Fatal("failed to verify valid membership proof")
	}
	if proof.Size() == 0 {
		t.Fatal("expected a non-zero sized membership proof")
	}

	// query for same event in previous snapshot, where it should not exist
	answer, event, proof, err = server.QueryMembership(events[0].Key, s1, vk)
	if err != nil {
		t.Fatalf("failed to perform a membership query: %s", err)
	}
	if answer {
		t.Fatal("got a true answer for a membership query that should have answered false")
	}
	if event != nil {
		t.Fatal("got an event for a membership query that should have not returned an event")
	}
	if !proof.Verify(events[0].Key, s1, s2, answer, event, vk) {
		t.Fatal("failed to verify valid membership proof")
	}

	// query for a random key in latest snapshot
	key := make([]byte, util.HashOutputLen)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("failed to read random bytes: %s", err)
	}
	answer, event, proof, err = server.QueryMembership(key, s2, vk)
	if err != nil {
		t.Fatalf("failed to perform a membership query: %s", err)
	}
	if answer {
		t.Fatal("got a true answer for a membership query that should have answered false")
	}
	if event != nil {
		t.Fatal("got an event for a membership query that should have not returned an event")
	}
	if !proof.Verify(key, s2, s2, answer, event, vk) {
		t.Fatal("failed to verify valid membership proof")
	}

	// query for the random key in a prior snapshot
	answer, event, proof, err = server.QueryMembership(key, s1, vk)
	if err != nil {
		t.Fatalf("failed to perform a membership query: %s", err)
	}
	if answer {
		t.Fatal("got a true answer for a membership query that should have answered false")
	}
	if event != nil {
		t.Fatal("got an event for a membership query that should have not returned an event")
	}
	if !proof.Verify(key, s1, s2, answer, event, vk) {
		t.Fatal("failed to verify valid membership proof")
	}

	/*
		Pruned queries
	*/

	// start with a prune query for events already inserted
	answer, pproof := server.QueryPrune(events, vk, true)
	if !pproof.Verify(events, answer, s2, vk) {
		t.Fatal("failed to verify a valid query prune proof")
	}
	if answer {
		t.Fatal("got a true reply to a prune query with old events")
	}
	if pproof.Size() == 0 {
		t.Fatal("expected a non-zero sized membership proof")
	}

	// randomise events
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	// query again
	answer, pproof = server.QueryPrune(events, vk, true)
	if !pproof.Verify(events, answer, s2, vk) {
		t.Fatal("failed to verify a valid query prune proof")
	}
	if !answer {
		t.Fatal("got a false reply to a prune query with random events")
	}

	/*
		Update using pruned queries
	*/

	s3u, err := pproof.Update(events, s2, sk)
	if err != nil {
		t.Fatalf("failed to update using prune: %s", err)
	}
	s3, err := author.Update(events, s2, sk)
	if err != nil {
		t.Fatalf("failed to update to 3: %s", err)
	}

	if !util.Equal(s3.Roots.History, s3u.Roots.History) {
		t.Fatal("Update (prune) produced a different history tree root")
	}
	if !util.Equal(s3.Roots.Treap, s3u.Roots.Treap) {
		t.Fatal("Update (prune) produced a different hash treap root")
	}
	if s3.Roots.Version != s3u.Roots.Version {
		t.Fatal("Update (prune) produced a different version")
	}

	/*
		Use RefreshVerify at the server
	*/

	if !server.RefreshVerify(events, s2, s3, vk) {
		t.Fatal("failed to refresh verify at server from 2 to 3")
	}
}

func TestBalloonDetails(t *testing.T) {
	// More specific tests for test coverage
	// setup for an initially empty Balloon for an author
	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	author, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}

	// update the Balloon with some events
	size := 10
	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	snapUpdate, err := author.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}

	// create a second balloon, but use Setup directly
	_, snapSetup, err := Setup(events, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}
	if snapUpdate.Roots.Version != snapSetup.Roots.Version ||
		!util.Equal(snapUpdate.Roots.History, snapSetup.Roots.History) ||
		!util.Equal(snapUpdate.Roots.Treap, snapSetup.Roots.Treap) {
		t.Fatal("snapshots using Update and Setup differ")
	}

	// Refresh
	server := NewBalloon(NewTestEventStorage())
	err = server.Refresh(nil, nil, s0, vk)
	if err != nil {
		t.Fatalf("failed to do initial refresh: %s", err)
	}
	err = server.Refresh(events, nil, snapUpdate, vk)
	if err == nil {
		t.Fatalf("did Refresh with wrong current snapshot")
	}
	err = server.Refresh(events, s0, snapUpdate, vk)
	if err != nil {
		t.Fatalf("failed to refresh from s0 to snapSetup: %s", err)
	}
	err = server.Refresh(events, nil, snapUpdate, vk)
	if err == nil {
		t.Fatalf("did Refresh with wrong current snapshot")
	}
	err = server.Refresh(events, snapUpdate, snapUpdate, vk)
	if err == nil {
		t.Fatalf("did Refresh with wrong current snapshot")
	}
	err = server.Refresh(events, s0, snapUpdate, vk)
	if err == nil {
		t.Fatalf("did Refresh with wrong current snapshot")
	}

	// Setup
	events = make([]Event, size)
	_, _, err = Setup(events, sk, vk, NewTestEventStorage())
	if err == nil {
		t.Fatal("successfully Setup with nil event keys and values")
	}

	// Update
	_, err = author.Update(events, snapUpdate, sk)
	if err == nil {
		t.Fatal("successfully Update with nil event keys and values")
	}
	_, err = author.Update(events, s0, sk)
	if err == nil {
		t.Fatal("successfully Update with old snapshot")
	}
	events = make([]Event, 0, size)
	_, err = author.Update(events, snapUpdate, sk)
	if err == nil {
		t.Fatal("successfully Update with no events")
	}

	// QueryMembership
	_, _, _, err = author.QueryMembership([]byte("too short key"), s0, vk)
	if err == nil {
		t.Fatalf("membership query for too short key: %s", err)
	}
	// flip every byte in the signature of the snapshot
	for i := range s0.Signature {
		s0.Signature[i] ^= 0x40
		_, _, _, err = author.QueryMembership(util.Hash([]byte("a valid key")), s0, vk)
		if err == nil {
			t.Fatalf("membership query for invalid signature: %s", err)
		}
		s0.Signature[i] ^= 0x40
	}
}

func TestMembershipQueryProofFlip(t *testing.T) {
	/*
		Create a Balloon with size events.
	*/

	size := 10
	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	balloon, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}
	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	s1, err := balloon.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}

	// create a membership query for an event that exists, such that
	// the proof consists of nodes in both the hash treap and the
	// history tree
	answer, event, proof, err := balloon.QueryMembership(events[0].Key, s1, vk)
	if err != nil {
		t.Fatalf("failed to perform membership query: %s", err)
	}

	if !proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
		t.Fatal("failed to verify valid membership proof and arguments")
	}

	/*
		OK, now we start systematically tampering with the proof and arguments
		to Verify to make sure that any changes are detected
	*/

	// flip every byte in the key
	for i := range events[0].Key {
		events[0].Key[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		events[0].Key[i] ^= 0x40
	}

	// flip every byte in the root of the history tree in the snapshot
	for i := range s1.Roots.History {
		s1.Roots.History[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Roots.History[i] ^= 0x40
	}

	// flip every byte in the root of the hash treap in the snapshot
	for i := range s1.Roots.Treap {
		s1.Roots.Treap[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Roots.Treap[i] ^= 0x40
	}

	// flip every byte in the signature of the snapshot
	for i := range s1.Signature {
		s1.Signature[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		if proof.Verify(events[0].Key, s0, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Signature[i] ^= 0x40
	}

	// flip every byte in the previous signature of the snapshot
	for i := range s1.Previous {
		s1.Previous[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		if proof.Verify(events[0].Key, s0, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Previous[i] ^= 0x40
	}

	// change the version of the snapshot
	s1.Roots.Version++
	if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	s1.Roots.Version--

	// flip answer
	if proof.Verify(events[0].Key, s1, s1, !answer, event, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}

	// flip every byte in the event key
	for i := range event.Key {
		event.Key[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		event.Key[i] ^= 0x40
	}

	// flip every byte in the event value
	for i := range event.Value {
		event.Value[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		event.Value[i] ^= 0x40
	}

	// flip every byte in the verification key
	for i := range vk {
		vk[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		vk[i] ^= 0x40
	}

	// flip every byte in event of the history tree proof
	for i := range proof.HistoryProof.Event {
		proof.HistoryProof.Event[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.HistoryProof.Event[i] ^= 0x40
	}

	// flip every byte in root of the history tree proof
	for i := range proof.HistoryProof.Root {
		proof.HistoryProof.Root[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.HistoryProof.Root[i] ^= 0x40
	}

	// flip the index history tree proof
	proof.HistoryProof.Index++
	if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	proof.HistoryProof.Index--

	// flip the version history tree proof
	proof.HistoryProof.Version++
	if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	proof.HistoryProof.Version--

	// for each node in the history tree proof
	for i := range proof.HistoryProof.Nodes {

		// flip each byte in the hash of the node
		for j := range proof.HistoryProof.Nodes[i].Hash {
			proof.HistoryProof.Nodes[i].Hash[j] ^= 0x40
			if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.HistoryProof.Nodes[i].Hash[j] ^= 0x40
		}

		// flip index in position
		proof.HistoryProof.Nodes[i].Position.Index++
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.HistoryProof.Nodes[i].Position.Index--

		// flip layer in position
		proof.HistoryProof.Nodes[i].Position.Layer++
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.HistoryProof.Nodes[i].Position.Layer--
	}

	// flip every byte in the key of the hash treap proof
	for i := range proof.TreapProof.Key {
		proof.TreapProof.Key[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.TreapProof.Key[i] ^= 0x40
	}

	// flip every byte in the value of the hash treap proof
	for i := range proof.TreapProof.Value {
		proof.TreapProof.Value[i] ^= 0x40
		if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.TreapProof.Value[i] ^= 0x40
	}

	// for each node in the hash treap proof
	for i := range proof.TreapProof.Nodes {

		// flip every byte in the hash of the node
		for j := range proof.TreapProof.Nodes[i].Hash {
			proof.TreapProof.Nodes[i].Hash[j] ^= 0x40
			if proof.Verify(events[0].Key, s1, s1, answer, event, vk) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.TreapProof.Nodes[i].Hash[j] ^= 0x40
		}

		// Note that we _cannot_ detect flips in a proof node's key and value when
		// the node's key and value are only used to place the node's hash either
		// left or right along the verified authenticated path in the hash treap.
		// This is not a security issue for the queries that make up Balloon,
		// but very well may be for other types of queries not specified in the
		// design of Balloon.
	}

}

func TestPruneQueryProofFlip(t *testing.T) {
	/*
		Create a Balloon with size events.
	*/
	size := 10
	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	balloon, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}
	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	s1, err := balloon.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}

	// a prune query for new random events, to get paths in both the hash treap
	// and the history tree
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	answer, proof := balloon.QueryPrune(events, vk, true)
	if !proof.Verify(events, answer, s1, vk) {
		t.Fatal("failed to verify a valid query prune proof")
	}
	if !answer {
		t.Fatal("got a false reply to a prune query with old events")
	}

	/*
		OK, now we start systematically tampering with the proof and arguments
		to Verify to make sure that any changes are detected
	*/

	// flip answer
	if proof.Verify(events, !answer, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}

	// flip every byte in the root of the history tree in the snapshot
	for i := range s1.Roots.History {
		s1.Roots.History[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Roots.History[i] ^= 0x40
	}

	// flip every byte in the root of the hash treap in the snapshot
	for i := range s1.Roots.Treap {
		s1.Roots.Treap[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Roots.Treap[i] ^= 0x40
	}

	// flip every byte in the signature of the snapshot
	for i := range s1.Signature {
		s1.Signature[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Signature[i] ^= 0x40
	}

	// flip every byte in the previous signature of the snapshot
	for i := range s1.Previous {
		s1.Previous[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Previous[i] ^= 0x40
	}

	// change the version of the snapshot
	s1.Roots.Version++
	if proof.Verify(events, answer, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	s1.Roots.Version--

	// flip every byte in the verification key
	for i := range vk {
		vk[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		vk[i] ^= 0x40
	}

	// flip every byte in the event key in the proof
	for i := range proof.Event.Key {
		proof.Event.Key[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Event.Key[i] ^= 0x40
	}

	// flip every byte in the event value in the proof
	for i := range proof.Event.Value {
		proof.Event.Value[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.Event.Value[i] ^= 0x40
	}

	// flip every byte in the key of the treap part of the proof
	for i := range proof.TreapProof.Key {
		proof.TreapProof.Key[i] ^= 0x40
		if proof.Verify(events, answer, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		proof.TreapProof.Key[i] ^= 0x40
	}

	// for each node in the hash treap proof
	for i := range proof.TreapProof.Nodes {

		// flip every byte in the hash of the node
		for j := range proof.TreapProof.Nodes[i].Hash {
			proof.TreapProof.Nodes[i].Hash[j] ^= 0x40
			if proof.Verify(events, answer, s1, vk) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			proof.TreapProof.Nodes[i].Hash[j] ^= 0x40
		}

		// Note that we _cannot_ detect flips in a proof node's key and value when
		// the node's key and value are only used to place the node's hash either
		// left or right along the verified authenticated path in the hash treap.
		// This is not a security issue for the queries that make up Balloon,
		// but very well may be for other types of queries not specified in the
		// design of Balloon.
	}

	// always possible to add no events
	if !proof.Verify(nil, true, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
}

func TestRefreshVerifyFlip(t *testing.T) {
	size := 10
	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	balloon, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}
	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}

	s1, err := balloon.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}

	server := NewBalloon(NewTestEventStorage())
	if !server.RefreshVerify(nil, nil, s0, vk) {
		t.Fatalf("failed to do initial refresh: %s", err)
	}
	clone := server.Clone()
	if !server.RefreshVerify(events, s0, s1, vk) {
		t.Fatalf("failed to do initial refresh: %s", err)
	}

	// flip events
	for i := range events {
		for j := range events[i].Key {
			// we need to do this since sort in RefreshVerify
			// may change the order of the slice based on key or value
			key := events[i].Key
			key[j] ^= 0x40
			if clone.RefreshVerify(events, s0, s1, vk) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			key[j] ^= 0x40
		}

		for j := range events[i].Value {
			value := events[i].Value
			value[j] ^= 0x40
			if clone.RefreshVerify(events, s0, s1, vk) {
				t.Fatal("verified an invalid proof and/or argument")
			}
			value[j] ^= 0x40
		}
	}

	// flip snapshot s0
	s0.Index++
	if clone.RefreshVerify(events, s0, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	s0.Index--
	s0.Roots.Version++
	if clone.RefreshVerify(events, s0, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	s0.Roots.Version--
	for i := range s0.Roots.History {
		s0.Roots.History[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s0.Roots.History[i] ^= 0x40
	}
	for i := range s0.Roots.Treap {
		s0.Roots.Treap[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s0.Roots.Treap[i] ^= 0x40
	}
	for i := range s0.Signature {
		s0.Signature[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s0.Signature[i] ^= 0x40
	}

	// flip snapshot s1
	s1.Index++
	if clone.RefreshVerify(events, s0, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	s1.Index--
	s1.Roots.Version++
	if clone.RefreshVerify(events, s0, s1, vk) {
		t.Fatal("verified an invalid proof and/or argument")
	}
	s1.Roots.Version--
	for i := range s1.Roots.History {
		s1.Roots.History[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Roots.History[i] ^= 0x40
	}
	for i := range s1.Roots.Treap {
		s1.Roots.Treap[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Roots.Treap[i] ^= 0x40
	}
	for i := range s1.Signature {
		s1.Signature[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Signature[i] ^= 0x40
	}
	for i := range s1.Previous {
		s1.Previous[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		s1.Previous[i] ^= 0x40
	}

	// flip verification key
	for i := range vk {
		vk[i] ^= 0x40
		if clone.RefreshVerify(events, s0, s1, vk) {
			t.Fatal("verified an invalid proof and/or argument")
		}
		vk[i] ^= 0x40
	}

	// see that the clone works
	if !clone.RefreshVerify(events, s0, s1, vk) {
		t.Fatal("broken clone")
	}
}

func TestClone(t *testing.T) {
	size := 10
	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	balloon, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}

	clone0 := balloon.Clone()
	if !clone0.latestsnapshot.Equal(s0) {
		t.Fatal("clone has different snapshot")
	}

	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}
	s1, err := balloon.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}
	s1c, err := clone0.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}
	if !s1c.Equal(s1) {
		t.Fatal("clone has different snapshot")
	}
}

func TestEqualSnapshot(t *testing.T) {
	size := 10
	sk, vk, err := Genkey()
	if err != nil {
		t.Fatalf("failed to generate keys: %s", err)
	}
	balloon, s0, err := Setup(nil, sk, vk, NewTestEventStorage())
	if err != nil {
		t.Fatalf("failed to setup balloon: %s", err)
	}
	events := make([]Event, size)
	for i := 0; i < size; i++ {
		k := make([]byte, util.HashOutputLen)
		_, err = rand.Read(k)
		if err != nil {
			t.Fatalf("failed to read random bytes: %s", err)
		}
		events[i].Key = k
		events[i].Value = util.Hash(k)
	}

	s1, err := balloon.Update(events, s0, sk)
	if err != nil {
		t.Fatalf("failed to update to s1: %s", err)
	}

	if !s1.Equal(s1) {
		t.Fatal("the smae snapshot is not equal with itself")
	}
	if s1.Equal(s0) {
		t.Fatal("two different snapshots are equal")
	}
}
