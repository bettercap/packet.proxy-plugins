# Packet Proxy Plugins

Plugins for the [packet.proxy](https://github.com/bettercap/bettercap/wiki/packet.proxy) module.

**IMPORTANT**

In order to be compiled correctly, plugin `.go` files need to be copied inside bettercap's source folder and compiled from there, otherwise you might have issues compiling due to dependency conflicts with the vendor folder.

**Compile**

1. Copy the plugin file inside bettercap's source folder.
2. Compile with `go build -buildmode=plugin plugin.file.go`, this will generate the file `plugin.file.so`.
