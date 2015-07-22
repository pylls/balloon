package main

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"

	"github.com/pylls/balloon"
	"github.com/pylls/balloon/util"
)

var sk, vk []byte
var cacheBalloon map[int]*balloon.Balloon
var cacheSnap map[int]*balloon.Snapshot

func init() {
	s, v, err := balloon.Genkey()
	if err != nil {
		panic(err)
	}
	sk = s
	vk = v

	cacheBalloon = make(map[int]*balloon.Balloon)
	cacheSnap = make(map[int]*balloon.Snapshot)
}

func reusableBalloon(size int) (ball *balloon.Balloon, snap *balloon.Snapshot) {
	_, exists := cacheBalloon[size]
	if !exists {
		events := make([]balloon.Event, size)
		for i := 0; i < size; i++ {
			events[i].Key = util.Hash(util.Itob(i))
			events[i].Value = util.Hash(util.Itob(i))
		}

		b, s, err := balloon.Setup(events, sk, vk)
		if err != nil {
			panic(err)
		}
		cacheBalloon[size] = b
		cacheSnap[size] = s
	}
	ball, _ = cacheBalloon[size]
	ball = ball.Clone()
	snap, _ = cacheSnap[size]
	return
}

var balloonSize int
var insertCount = 1

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Printf("running with %d CPU cores\n", runtime.NumCPU())

	b := []int{util.Pow(2, 10), util.Pow(2, 15), util.Pow(2, 20)}
	c := []int{10, 100, 1000}

	fmt.Printf("\ntime to run query(prune) for entry counts %d\n", c)
	queryTime := make([][]float64, len(b))
	for i := 0; i < len(b); i++ {
		balloonSize = b[i]
		queryTime[i] = make([]float64, len(c))
		fmt.Printf("\tBalloon size %10d: ", b[i])
		for j := 0; j < len(c); j++ {
			insertCount = c[j]

			result := testing.Benchmark(BenchmarkQueryPrune)

			queryTime[i][j] = float64(result.T.Nanoseconds()) / float64(result.N*1000*1000)
			fmt.Printf("%6.2f ms/op [%6d samples]", queryTime[i][j], result.N)

			if j+1 < len(c) {
				fmt.Printf(", ")
			} else {
				fmt.Printf("\n")
			}
		}
	}

	fmt.Printf("\ntime to run verify(prune) for entry counts %d\n", c)
	for i := 0; i < len(b); i++ {
		balloonSize = b[i]
		fmt.Printf("\tBalloon size %10d: ", b[i])
		for j := 0; j < len(c); j++ {
			insertCount = c[j]

			result := testing.Benchmark(BenchmarkVerifyPrune)
			// print time
			fmt.Printf("%6.2f ms/op [%6d samples]",
				float64(result.T.Nanoseconds())/float64(result.N*1000*1000), result.N)

			if j+1 < len(c) {
				fmt.Printf(", ")
			} else {
				fmt.Printf("\n")
			}
		}
	}

	fmt.Printf("\ntime to run update* for entry counts %d\n", c)
	for i := 0; i < len(b); i++ {
		balloonSize = b[i]
		fmt.Printf("\tBalloon size %10d: ", b[i])
		for j := 0; j < len(c); j++ {
			insertCount = c[j]

			result := testing.Benchmark(BenchmarkUpdate)

			// the idea is to run Ballon.insert and substract the time it takes to make the proof
			fmt.Printf("%6.2f ms/op [%6d samples]",
				float64(result.T.Nanoseconds())/float64(result.N*1000*1000)-queryTime[i][j], result.N)

			if j+1 < len(c) {
				fmt.Printf(", ")
			} else {
				fmt.Printf("\n")
			}
		}
	}

	// reverse the order of the balloons for prettier graph
	b = []int{util.Pow(2, 20), util.Pow(2, 15), util.Pow(2, 10)}

	fmt.Println("\ninsert proof size (KiB) with pruning")
	fmt.Println("insert, Pow(2, 20) Balloon, Pow(2, 15) Balloon, Pow(2, 10) Balloon")
	d := []int{1, 10, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}
	for i := 0; i < len(d); i++ {
		insertCount = d[i]
		fmt.Printf("%d, ", insertCount)

		// get events to query for with unique keys
		events := make([]balloon.Event, insertCount)
		for j := 0; j < insertCount; j++ {
			events[j].Key = make([]byte, util.HashOutputLen)
			_, err := rand.Read(events[j].Key)
			if err != nil {
				panic(err)
			}
			events[j].Value = util.Hash(events[j].Key)
		}
		for j := 0; j < len(b); j++ {
			// create balloon of size

			ds, _ := reusableBalloon(b[j])
			// insert the events
			answer, proof := ds.QueryPrune(events, vk, true)
			if !answer {
				panic("wrong answer")
			}

			// check proof size
			fmt.Printf("%d", proof.Size()/1024)

			if j+1 < len(b) {
				fmt.Printf(", ")
			} else {
				fmt.Printf("\n")
			}
		}
	}

	fmt.Println("\ninsert proof size (KiB) no pruning")
	fmt.Println("insert, Pow(2, 20) Balloon, Pow(2, 15) Balloon, Pow(2, 10) Balloon")
	for i := 0; i < len(d); i++ {
		insertCount = d[i]
		fmt.Printf("%d, ", insertCount)

		// get events to query for with unique keys
		events := make([]balloon.Event, insertCount)
		for j := 0; j < insertCount; j++ {
			events[j].Key = make([]byte, util.HashOutputLen)
			_, err := rand.Read(events[j].Key)
			if err != nil {
				panic(err)
			}
			events[j].Value = util.Hash(events[j].Key)
		}
		for j := 0; j < len(b); j++ {
			// create balloon of size

			ds, _ := reusableBalloon(b[j])
			// insert the events
			answer, proof := ds.QueryPrune(events, vk, false)
			if !answer {
				panic("wrong answer")
			}

			// check proof size
			fmt.Printf("%d", proof.Size()/1024)

			if j+1 < len(b) {
				fmt.Printf(", ")
			} else {
				fmt.Printf("\n")
			}
		}
	}
}

// BenchmarkUpdate benchmarks performing an update.
func BenchmarkUpdate(b *testing.B) {
	events := make([]balloon.Event, insertCount)
	for j := 0; j < insertCount; j++ {
		events[j].Key = make([]byte, util.HashOutputLen)
		_, err := rand.Read(events[j].Key)
		if err != nil {
			panic(err)
		}
		events[j].Value = util.Hash(events[j].Key)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		ds, current := reusableBalloon(balloonSize)
		b.StartTimer()
		_, err := ds.Update(events, current, sk)
		if err != nil {
			panic(err)
		}
	}
}

// BenchmarkQueryPrune benchmarks performing a prune query.
func BenchmarkQueryPrune(b *testing.B) {
	// create reusable Balloon
	ds, _ := reusableBalloon(balloonSize)

	// get events to query for with unique keys
	events := make([]balloon.Event, insertCount)
	for j := 0; j < insertCount; j++ {
		events[j].Key = make([]byte, util.HashOutputLen)
		_, err := rand.Read(events[j].Key)
		if err != nil {
			panic(err)
		}
		events[j].Value = util.Hash(events[j].Key)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		answer, _ := ds.QueryPrune(events, vk, true)
		if !answer {
			panic("invalid proof")
		}
	}
}

// BenchmarkVerifyPrune benchmarks verifying a prune proof.
func BenchmarkVerifyPrune(b *testing.B) {
	// create reusable Balloon
	ds, current := reusableBalloon(balloonSize)

	// get events to query for with unique keys
	events := make([]balloon.Event, insertCount)
	for j := 0; j < insertCount; j++ {
		events[j].Key = make([]byte, util.HashOutputLen)
		_, err := rand.Read(events[j].Key)
		if err != nil {
			panic(err)
		}
		events[j].Value = util.Hash(events[j].Key)
	}

	answer, proof := ds.QueryPrune(events, vk, true)
	if !answer {
		panic("invalid proof")
	}

	b.ResetTimer()
	// query for all of them
	for i := 0; i < b.N; i++ {
		if !proof.Verify(events, answer, current, vk) {
			panic("failed to verify valid proof")
		}
	}
}

// MbPerSec is based on http://golang.org/src/testing/benchmark.go?s=6649:6689#L248
func MbPerSec(bytes int64, N int, duration float64) float64 {
	return (float64(bytes) * float64(N) / (1024 * 1024)) / duration
}

// EventsPerSec is based on http://golang.org/src/testing/benchmark.go?s=6649:6689#L248
func EventsPerSec(N, count int, duration float64) float64 {
	return float64(N) * float64(count) / duration
}
