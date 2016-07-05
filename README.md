# Balloon [![Build Status](https://travis-ci.org/pylls/balloon.svg?branch=master)](https://travis-ci.org/pylls/balloon) [![GoDoc](https://godoc.org/github.com/pylls/balloon?status.png)](https://godoc.org/github.com/pylls/balloon) [![Coverage Status](https://coveralls.io/repos/github/pylls/balloon/badge.svg?branch=master)](https://coveralls.io/github/pylls/balloon?branch=master)
A forward-secure append-only persistent authenticated data structure.
This is a proof-of-concept implementation, please do not use for anything serious.

### Design
Balloon is composed of a history tree (like Certificate Transparency) and a
hash treap (think authenticated index).
Please read [the paper](https://eprint.iacr.org/2015/007) for details. To run
and reproduce parts of the benchmark from the paper, see the
[paper-bench branch](https://github.com/pylls/balloon/tree/paper-bench).

### License
Apache 2.0. The hash treap implementation is based on the treap implementation
by [Steve Yen](https://github.com/steveyen/gtreap) under the MIT license.
