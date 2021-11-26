# sgx-dl

## Setup

1. `git clone <this-repo>`
3. `mkdir build`
4. `cd build`
5. `cmake ..`
6. `make`


## Compile Rust code:
`rustc -Cpanic=abort --emit obj -O lib.rs`


## Example apps

### bin/exampleapp test

Simple small test of the library

### bin/exampleapp base & bin/examplepp patch

Baseline and path for function executions benchmark, not used in the paper

### bin/exampleappbench

Microbenchmark of the paper, add and load 10000 empty functions
