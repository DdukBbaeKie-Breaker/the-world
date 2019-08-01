BUILD_DIR :=./build
HEADER_DIR :=./header
SOURCE_DIR :=./source

all : the-world

the-world: main.o
	g++ -g -o ${BUILD_DIR}/the-world ${BUILD_DIR}/packet.o ${BUILD_DIR}/main.o -lnetfilter_queue

main.o : packet.o
	g++ -g -c -o ${BUILD_DIR}/main.o ${SOURCE_DIR}/main.cpp

packet.o: MakeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/packet.o ${SOURCE_DIR}/packet.cpp

MakeBuildFolder:
	mkdir -p ${BUILD_DIR}

clean:
	rm -f ${BUILD_DIR}/*
	rmdir ${BUILD_DIR}
