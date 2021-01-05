FROM gcc

RUN apt-get purge -y cmake

WORKDIR /tmp/cmake
RUN wget https://cmake.org/files/v3.19/cmake-3.19.1.tar.gz && \
    tar -xzvf cmake-3.19.1.tar.gz > /dev/null

WORKDIR cmake-3.19.1
RUN ./bootstrap && \
    make -j4 && \
    make install

WORKDIR /
RUN rm -rf /tmp/cmake

RUN mkdir -p /dstu-engine/build
COPY dstulib         dstu-engine/dstulib
COPY engine          dstu-engine/engine
COPY keylib          dstu-engine/keylib
COPY tests           dstu-engine/tests
COPY Doxyfile        dstu-engine/Doxyfile
COPY CMakeLists.txt  dstu-engine/CMakeLists.txt
WORKDIR /dstu-engine/build
RUN cmake ..
RUN make
RUN make install

WORKDIR /

#CMD exec /bin/bash -c "trap : TERM INT; sleep infinity & wait"
