# sgx-dl

## Setup

1. `git clone <this-repo>`
3. `mkdir build`
4. `cd build`
5. `cmake ..`
6. `make`


## Example apps

Navigate into `build/bin`

### `exampleapp test`

Simple small test of the library

### `exampleapp base` and `examplepp patch`

Baseline and path for function executions benchmark, not used in the paper

### `exampleappbench`

Microbenchmark of the paper, add and load 10000 empty functions
