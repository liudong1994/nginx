VERSION_ID=1.0.0 

ifeq ($(GCOV_ON),1)
	CC = g++ -ftest-coverage -fprofile-arcs
	CXX = $(CC)
else
	CC = g++ -g
	CXX = $(CC)
endif


#c++11
C11=/opt/rh/devtoolset-3/root/usr/bin/
PATH:=$(C11):$(PATH)

INC             = /home/homework/include
SRC			    = ./src
DEPS            = ./deps
PLUGIN          = ./plugin
HANDLER         = $(SRC)/handler

PROGRAM_NAME = server
TARGET       = $(PLUGIN)/$(PROGRAM_NAME)

CFLAGS = -std=c++11 -O2 -fPIC -W -Wall -Werror 
#CXXFLAGS = -std=c++11 -fPIC -W -Wall -Werror -Wno-unused-parameter  -D_LARGEFILE64_SOURCE -D_GLIBCXX_USE_CXX11_ABI=0 \

CXXFLAGS = -std=c++11 -O2 -fPIC -W -Wall -Werror -Wno-unused-parameter  -D_LARGEFILE64_SOURCE -D_GLIBCXX_USE_CXX11_ABI=0 \
		   -D_FILE_OFFSET_BITS=64 -D_REENTRANT -D__VERSION_ID__="\"$(VERSION_ID)\""


LIBS = -L/home/homework/lib64   \
       -L/usr/lib               \
       -L/usr/lib64/mysql		\
	   -lrt                     \
	   -lpthread                \
	   -lcrypto                 \
	   -luuid                   

TEST_LIBS = -lgtest -lgtest_main -lgmock

CPPFLAGS = -I$(INC)             \
		   -I$(DEPS)            \
		   -I$(SRC)   			\
		   -I$(HANDLER)         	

OBJS = $(HANDLER)/handler_process.o                         \
	   $(HANDLER)/context_process.o						    \
	   $(SRC)/service.o                     				\
	   $(DEPS)/file_util.o                                  \
	   $(DEPS)/url_util.o

all: $(TARGET)

$(TARGET):$(OBJS)
	@mkdir -p $(PLUGIN)
	$(CXX) -shared $^ -o $@ $(LIBS)


.PHONY: clean install

install:
	@mkdir -p /home/homework/adplatform/adx_config/conf
	@mkdir -p /home/homework/adplatform/adx_config/bin
	@mkdir -p /home/homework/adplatform/adx_config/plugin
	cp -rf conf/* /home/homework/adplatform/adx_config/conf
	cp -rf bin/* /home/homework/adplatform/adx_config/bin
	rm -rf /home/homework/adplatform/adx_config/plugin/*
	cp -rf plugin/* /home/homework/adplatform/adx_config/plugin

clean:
	@rm -rf $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET)
	@rm -rf *.log

