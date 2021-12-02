# sgx-dl

## Paper

The paper will be presented at Middleware 2021 and is available here: https://dl.acm.org/doi/10.1145/3464298.3476134

Please cite us if you use our work in your research:
```
@inproceedings{weichbrodt2021middleware,
  author = {Weichbrodt, Nico and Heinemann, Joshua and Almstedt, Lennart and Aublin, Pierre-Louis and Kapitza, R\"{u}diger},
  title = {{sgx-Dl: Dynamic Loading and Hot-Patching for Secure Applications: Experience Paper}},
  year = {2021},
  doi = {10.1145/3464298.3476134},
  booktitle = {Proceedings of the 22nd International Middleware Conference},
  series = {Middleware '21}
}
```


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
