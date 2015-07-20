# Balloon [![Build Status](https://travis-ci.org/pylls/balloon.svg?branch=master)](https://travis-ci.org/pylls/balloon) [![GoDoc](https://godoc.org/github.com/pylls/balloon?status.png)](https://godoc.org/github.com/pylls/balloon)
A forward-secure append-only persistent authenticated data structure.
This is a proof-of-concept implementation, please do not use for anything serious.

### Design
Balloon is composed of a history tree (like Certificate Transparency) and a
hash treap (think authenticated index).
Please read [the paper](https://eprint.iacr.org/2015/007) for details.

### License
Apache 2.0. The hash treap implementation is based on the treap implementation
by [Steve Yen](https://github.com/steveyen/gtreap) under the MIT license.
