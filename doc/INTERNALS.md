# TODO FIXME

## Code

The code is written as "dependency-free" Python, external libraries are only used
for testing.

It is written in a loosely functional style as a series of data transforms.

## Design constraits

Some design decisions: 

* We don't actually support port ranges. In general wide port ranges should only
  be required to implement return traffic. 

