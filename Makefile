all: gopacket.example.so tls.downgrade.so

%.so: %.go
	go build -buildmode=plugin $<

clean:
	rm -rf *.so
