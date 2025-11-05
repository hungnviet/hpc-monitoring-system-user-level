#include <iostream>
#include <string>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <vector>
#include <sstream>
#include <thread>
#include <chrono>
#include <iomanip>
/**
 * @brief Executes a shell command and returns its standard output.
 * @param cmd The command to execute.
 * @return The stdout from the command.
 * @throws std::runtime_error if popen() fails.
 */
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

/**
 * @brief Clears the terminal screen using ANSI escape codes.
 */
void clearScreen() {
    std::cout << "\033[H\033[2J" << std::flush;
}

/**
 * @brief Fetches and prints global GPU stats (Power, Temp, Total Load).
 */
void printGlobalStats() {
    std::string output;
    try {
        output = exec("nvidia-smi --query-gpu=power.draw,temperature.gpu,utilization.gpu --format=csv,noheader,nounits");
    } catch (const std::exception& e) {
        std::cerr << "Failed to run nvidia-smi for global stats: " << e.what() << std::endl;
        return;
    }

    // Trim trailing newline
    if (!output.empty() && output.back() == '\n') {
        output.pop_back();
    }

    // Split the line by ", "
    std::vector<std::string> parts;
    std::stringstream ss(output);
    std::string part;
    while (std::getline(ss, part, ',')) {
        // nvidia-smi output has a space after the comma
        if (part.front() == ' ') {
            part.erase(0, 1);
        }
        parts.push_back(part);
    }

    std::cout << "--- Global GPU Stats (Total) ---" << std::endl;
    if (parts.size() == 3) {
        printf("Power Draw: %s W\n", parts[0].c_str());
        printf("Temperature: %s C\n", parts[1].c_str());
        printf("Total Load: %s %%\n", parts[2].c_str());
    } else {
        std::cout << "Could not parse global stats." << std::endl;
    }
    std::cout << "----------------------------------\n" << std::endl;
}

/**
 * @brief Fetches and prints per-process stats (PID, User, CMD, VRAM, Load).
 */
void printProcessStats() {
    std::string output;
    try {
        output = exec("nvidia-smi --query-compute-apps=pid,uname,name,used_gpu_memory,utilization.gpu --format=csv,noheader,nounits");
    } catch (const std::exception& e) {
        std::cerr << "Failed to run nvidia-smi for processes: " << e.what() << std::endl;
        return;
    }

    std::cout << "--- Per-Process GPU Stats ---" << std::endl;
    // Print header
    printf("PID\t USER\t\t CMD\t\t\t VRAM (MiB)\t GPU LOAD (%%)\n");
    printf("---------------------------------------------------------------------------------\n");

    std::stringstream ss(output);
    std::string line;
    bool foundProcesses = false;

    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        foundProcesses = true;

        std::vector<std::string> parts;
        std::stringstream line_ss(line);
        std::string part;
        while (std::getline(line_ss, part, ',')) {
            // nvidia-smi output has a space after the comma
            if (part.front() == ' ') {
                part.erase(0, 1);
            }
            parts.push_back(part);
        }

        if (parts.size() == 5) {
            printf("%s\t %-10s\t %-20s\t %-10s\t %-10s\n",
                   parts[0].c_str(), ///PID
                   parts[1].c_str(), /// USER   
                   parts[2].c_str(), /// CMD
                   parts[3].c_str(), /// VRAM
                   parts[4].c_str());/// GPU LOAD
        }
    }

    if (!foundProcesses) {
        std::cout << "No active GPU compute processes found." << std::endl;
    }
}

int main() {
    try {
        while (true) {
            clearScreen();
            std::cout << "### GPU Process Monitor Dashboard (C++) ### (Press Ctrl+C to quit)" << std::endl;
            std::cout << "Refreshing every 1 second..." << std::endl << std::endl;

            printGlobalStats();
            printProcessStats();

            // Wait for 1 second
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}