# hydrogen-micropython

## Table of Contents
+ [About](#about)
+ [Getting Started](#getting_started)
+ [Usage](#usage)
+ [module documentation](#doc)

## About <a name = "about"></a>
Very recently [libhydrogen](https://github.com/jedisct1/libhydrogen)
was added to [micropython](https://github.com/micropython/micropython)
for providing encrypted and signed firmware upgrades.

See: [this-pull-request](https://github.com/micropython/micropython/pull/6771)

This C-Module is intended to lift the C functionality in libhydrogen
to be usable from micropython.

Currently key-generation and signing and verifying signatures is supported.

## Getting Started <a name = "getting_started"></a>

### Prerequisites
This is designed for micropython.

```
git clone --recurse-submodules https://github.com/micropython/micropython.git
```

to compile the project, [make](https://www.gnu.org/software/make/),
[gcc](https://gcc.gnu.org/) and [arm-none-eabi-gcc](https://gcc.gnu.org/) is required,
install them from your package manager

### Installing
[hydrogen-micropython](https://github.com/peterzuger/hydrogen-micropython) will work on
the stm32 and the unix port.

First create a modules folder next to your copy of [micropython](https://github.com/micropython/micropython).

```
project/
├── modules/
│   └──hydrogen-micropython/
│       ├──...
│       └──micropython.mk
└── micropython/
    ├──ports/
   ... ├──stm32/
      ...
```

And now put this project in the modules folder.

```
cd modules
git clone https://gitlab.com/peterzuger/hydrogen-micropython.git
```

Now that all required changes are made, it is time to build [micropython](https://github.com/micropython/micropython),
for this cd to the top level directory of [micropython](https://github.com/micropython/micropython).
From here, first the mpy-cross compiler has to be built:
```
make -C mpy-cross
```

once this is built, compile your port with:
```
make -C ports/your port name here/ USER_C_MODULES=../modules CFLAGS_EXTRA=-DMODULE_HYDROGEN_ENABLED=1
```

and you are ready to use hydrogen.

## Usage <a name = "usage"></a>
The module is available by just importing hydrogen:
```
import hydrogen
```

The module documentation is available soon.

## Documentation <a name = "doc"></a>
coming soon
