CXX=g++
CXXFLAGS=-Wall -pedantic -std=c++14 -I. -O3
LD=g++
LDFLAGS=-Wall -pedantic -std=c++14

multiblock_test: multiblock_test.o oneblockshamir.o multiblock.o rijndael.o get_insecure_randomness.o sha256.o
	$(LD) $(LDFLAGS) -o $@ $^

oneblockshamir_test: oneblockshamir_test.o oneblockshamir.o get_insecure_randomness.o rijndael.o
	$(LD) $(LDFLAGS) -o $@ $^

rijndael_test: rijndael.o rijndael_test.o
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.cpp %.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

sha256.o: sha256.cpp
multiblock.o: multiblock.cpp
multiblock_test.o: multiblock_test.cpp multiblock.cpp
rijndael.o: rijndael.cpp rijndael.h
rijndael_test.o: rijndael_test.cpp rijndael.h
oneblockshamir.o: oneblockshamir.cpp oneblockshamir.h
oneblockshamir_test.o: oneblockshamir_test.cpp oneblockshamir.h
get_insecure_randomness.o: get_insecure_randomness.cpp get_insecure_randomness.h

check: rijndael_test
	./rijndael_test

clean:
	rm -f *.o rijndael_test oneblockshamir_test multiblock_test
