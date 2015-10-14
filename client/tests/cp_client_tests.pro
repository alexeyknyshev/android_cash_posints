QT += core network testlib

SOURCES = ts_serverapi.cpp ../src/serverapi.cpp
HEADERS = ../src/serverapi.h

QMAKE_CXXFLAGS += -std=c++11

RESOURCES += \
    test_data.qrc
