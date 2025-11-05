# Makefile for building the C++ GPU monitor

# C++ compiler
CXX = g++
# C++11 is needed for std::this_thread, std::chrono, std::unique_ptr
CXXFLAGS = -std=c++11 -Wall -O2
# Link the pthread library for std::this_thread
LDFLAGS = -lpthread

# Target binary name
TARGET = gpu_process_monitor_cpp

# Source file
SRC = gpu_process_monitor.cpp

.PHONY: all build run clean

# Build the application (default)
all: build

# Compile the C++ program
build: $(TARGET)

$(TARGET): $(SRC)
	@echo "Building $(TARGET)..."
	@$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete."

# Build and run the application
run: build
	@echo "Running $(TARGET)..."
	@./$(TARGET)

# Clean the build artifacts
clean:
	@echo "Cleaning..."
	@rm -f $(TARGET)