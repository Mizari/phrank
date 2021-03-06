# Post HexRays ANalysis Kit

## About
Phrank helps with structure analysis and function pointers. Phrank works on top of HexRays ctrees.

## Installation:
1) Copy/link phrank.py to IDAPRO/plugins/
2) Copy/link phrank and phrank_apy.py to IDAPRO/python/3/ folder  

It is also possible to just run phrank.py during analysis without installation

## Capabilities
1) Analyze pointer variable: automatically calculate pointed structure size, create new structure and set variable type
<p align='center'>
<img src='pictures/before.PNG'>
<img src='pictures/after.PNG'>
</p>
2) Analyze C++ classes with multiple inheritance: detect multiple inheritance among C++ classses, detect virtual tables, create structures for virtual tables, detect and set C++ objects in functions

## How to use
There are currently two ways to use phrank: hotkey actions (described [here](https://github.com/Mizari/phrank/wiki/Phrank-plugin-and-actions) and in comments [here](https://github.com/Mizari/phrank/blob/master/phrank.py)) and phrank_api (described in docstring comments [here](https://github.com/Mizari/phrank/blob/master/phrank_api.py)).
