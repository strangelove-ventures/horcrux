# ledger-go

[![CircleCI](https://circleci.com/gh/ZondaX/ledger-go.svg?style=svg)](https://circleci.com/gh/ZondaX/ledger-go)
[![Build status](https://ci.appveyor.com/api/projects/status/m4wn7kuuuu98b3uh/branch/master?svg=true)](https://ci.appveyor.com/project/zondax/ledger-go/branch/master)
[![Build Status](https://travis-ci.org/ZondaX/ledger-goclient.svg?branch=master)](https://travis-ci.org/ZondaX/ledger-go)

This project provides a library to connect to ledger devices. 

It handles USB (HID) communication and APDU encapsulation.

Linux, OSX and Windows are supported.

# Get source
Apart from cloning, be sure you install dep dependency management tool
https://github.com/golang/dep

## Setup
Update dependencies using the following:
```
dep ensure 
```

# Building
```
go build
```
