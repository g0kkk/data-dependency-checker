# Data-dependency-checker

Data Dependency Checker (DDC) was developed to help one in identifying if the value being passed onto a register at a specific instruction is used
anywhere in future to decide the control flow of the program. 

## Implementation

DDC is developed on top of [angr](https://github.com/angr/angr) which is open-source. DDC uses symbolic exploration to 
identify whether the value at the destination register of the given instruction is being used in any call, test or compare
in future but within the same function. 

DDC as of now only supports **x86-64** and **x86** with support for more architectures coming soon. 

## Installation & Usage

### Installation

I suggest to install this in a virtualenv and to install, run `pip3 install -r requirements.txt` followed by `pip3 install -e .`

### Usage

There is a helper script (`run_ddc.py`) provided which accepts the following arguments:

```angular2html
-b : Path to target binary
-a : Address at which the check needs to be done
-p : Arch (currently supports x86 and x86_64)
```

Inside `test_binaries`, a script to run on the program `hello` is included. 