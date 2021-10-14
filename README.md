# Elasticlave

**Elasticlave** is a Trusted Execution Environment (TEE) design which enables efficient cross-enclave data sharing.
This repository contains the prototype implementation based on [Keystone](https://keystone-enclave.org/) as described in "Elasticlave : An Efficient Memory Model for Enclaves" (Usenix Security Symposium 2022, [preprint version on arXiv](https://arxiv.org/abs/2010.08440)). For simplicity, we directly refer to this prototype implementation as Elasticlave in this document.

We support two options for running Elasticlave:
  1. On a RISC-V SoC simulated with [FireSim](https://fires.im/). This can give accurate performance data and is therefore suitable for performance benchmarking. However, it is generally much slower than the second option.
  2. On a system emulated with QEMU. It cannot provide accurate performance data but runs fast and is great for testing the functionality.

The setup of Elasticlave differs depending on the option chosen.

## On FireSim
### Requirements and Dependencies
You need to set up FireSim on AWS EC2. Elasticlave has been tested on FireSim 1.9.0. Please refer to the [FireSim documentation](https://docs.fires.im/en/1.9.0/) for instructions.

We have dockerised the remaining software dependencies.
See the [official website of Docker](https://www.docker.com/) for instructions on installing Docker on your system.

### Building
```bash
git clone https://github.com/jasonyu1996/elasticlave.git
cd elasticlave
git submodule update --init --recursive
./docker.sh
```

### Launching
```bash
./run-firesim.sh
```

## On QEMU

### Requirements and Dependencies
We have dockerised most of the software dependencies, so there should be little problem running Elasticlave on any x86-64 Linux distribution with **Docker** installed.
See the [official website of Docker](https://www.docker.com/) for instructions on installing Docker on your system.

### Building
```bash
git clone https://github.com/jasonyu1996/elasticlave.git
cd elasticlave
git submodule update --init --recursive
./docker.sh
```

### Launching
```bash
./docker-run.sh ./run.sh
```

When prompted for the login, enter `root`. The corresponding password is `sifive`.

## Benchmarks

### Configuration

You can configure which benchmarks to include in the built file system. To achieve this, edit the file ``KEYSTONE_FOLDER/tests/tests/mkconfig.mk`` and uncomment the names of the benchmarks you want to include.

### Available Benchmarks

Below are lists of the benchmarks included in this repository.

#### Synthetic Benchmarks

##### Thread Synchronisation

| Benchmark set | Elasticlave (spinlock) | Elasticlave (futex) | Spatial isolation | Native non-TEE  |
| ------------- | ---------------------- | ------------------- | ----------------- | --------------- |
| Lock          | ``lock``               | ``lock-futex``      | ``lock-spatial``  | ``lock-native`` |

##### Data Sharing Patterns

| Benchmark set     | Elasticlave        | Elasticlave (no lock bit) | Spatial isolation           |
| ----------------- | ------------------ | ------------------------- | --------------------------- |
| Producer-consumer | ``icall-consumer`` | ``icall-consumer-ne``     | ``icall-consumer-baseline`` |
| Client-server     | ``icall-server``   | ``icall-server-ne``       | ``icall-server-baseline``   |
| Proxy             | ``icall-proxy-3``  | ``icall-proxy-3-ne``      | ``icall-proxy-3-baseline``  |

#### IOZone

| Benchmark set | Elasticlave | Spatial isolation   | Native non-TEE    |
| ------------- | ----------- | ------------------- | ----------------- |
| IOZone        | ``iozone``  | ``iozone-baseline`` | ``iozone-native`` |

## Third-Party Components
The implementation provided in this repository is based on [Keystone](https://keystone-enclave.org/).

This repository includes the third-party benchmark [IOZone](https://www.iozone.org/). The licence is included in its source files.

---------

Below is the original README from Keystone, which can also be valuable fo reference.


# Keystone: An Open-Source Secure Enclave Framework for RISC-V Processors

![Documentation Status](https://readthedocs.org/projects/keystone-enclave/badge/)
[![Build Status](https://travis-ci.org/keystone-enclave/keystone.svg?branch=master)](https://travis-ci.org/keystone-enclave/keystone/)

Visit [Project Website](https://keystone-enclave.org) for more information.

`master` branch is for public releases.
`dev` branch is for development use (up-to-date but may not fully documented until merged into `master`).

# Documentation

See [docs](http://docs.keystone-enclave.org) for getting started.

# Contributing

See CONTRIBUTING.md
