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
// <iomanip> is still not needed

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

    if (!output.empty() && output.back() == '\n') {
        output.pop_back();
    }

    std::vector<std::string> parts;
    std::stringstream ss(output);
    std::string part;
    while (std::getline(ss, part, ',')) {
        if (!part.empty() && part.front() == ' ') {
            part.erase(0, 1);
        }
        parts.push_back(part);
    }

    std::cout << "--- Global GPU Stats ---" << std::endl;
    if (parts.size() == 3) {
        printf("Power Draw:  %s W\n", parts[0].c_str());
        printf("Temperature: %s C\n", parts[1].c_str());
        printf("Total Load:  %s %%\n", parts[2].c_str());
    } else {
        std::cout << "Could not parse global stats." << std::endl;
    }
    std::cout << "------------------------\n" << std::endl;
}

/**
 * @brief Fetches and prints per-process GPU stats using 'pmon'.
 */
void printProcessStats() {
    std::string output;
    try {
        // Use -c 1 to get a single snapshot and then exit
        output = exec("nvidia-smi pmon -c 1");
    } catch (const std::exception& e) {
        std::cerr << "Failed to run nvidia-smi for process stats: " << e.what() << std::endl;
        return;
    }

    std::cout << "--- GPU Process Monitor (pmon) ---" << std::endl;
    
    // The output from pmon is already formatted for a terminal,
    // so we can just print it directly.
    std::cout << output;
    
    // Add a newline if the output didn't end with one
    if (!output.empty() && output.back() != '\n') {
        std::cout << std::endl;
    }
    std::cout << "------------------------------------" << std::endl;
}


int main() {
    try {
        while (true) {
            clearScreen();
            printGlobalStats();
            printProcessStats();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}