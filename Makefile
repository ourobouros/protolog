APXS = /usr/sbin/apxs

all: .libs/protolog.so

# --- Protocol buffer

apachelog.pb-c.c apachelog.pb-c.h: apachelog.proto
	protoc-c --c_out=. apachelog.proto

# --- Apache DSO

.libs/protolog.so: protolog.c apachelog.pb-c.c
	$(APXS) -c $^ -lprotobuf-c

# ---

clean:
	rm -rf .libs *.a *.la *.lo *.slo *.o *.pb-c.h *.pb-c.c *.gch *.loT
