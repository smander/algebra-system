#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <set>

// DynInst headers
#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_process.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h"
#include "BPatch_basicBlock.h"
#include "Instruction.h"
#include "InstructionDecoder.h"

using namespace Dyninst;
using namespace Dyninst::ParseAPI;
using namespace Dyninst::InstructionAPI;

class DynInstTracer {
private:
    BPatch bpatch;
    BPatch_process* process;
    std::string outputFile;
    std::ofstream output;
    
    // Get current timestamp in microseconds
    long long getTimestamp() {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        return std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
    }
    
    // Convert bytes to hex string
    std::string bytesToHex(const unsigned char* bytes, size_t len) {
        std::stringstream ss;
        for (size_t i = 0; i < len; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Write JSON event to output
    void writeEvent(const std::string& kind, const std::string& address, 
                   const std::string& mnemonic, const std::string& bytes, 
                   int size, const std::string& function = "", 
                   const std::string& binary = "") {
        if (output.is_open()) {
            output << "{"
                   << "\"ts\": " << getTimestamp() << ", "
                   << "\"kind\": \"" << kind << "\", "
                   << "\"address\": \"" << address << "\", "
                   << "\"mnemonic\": \"" << mnemonic << "\", "
                   << "\"bytes\": \"" << bytes << "\", "
                   << "\"size\": " << size;
            if (!function.empty()) {
                output << ", \"function\": \"" << function << "\"";
            }
            if (!binary.empty()) {
                output << ", \"binary\": \"" << binary << "\"";
            }
            output << "}\n";
            output.flush();
        }
    }
    
public:
    DynInstTracer(const std::string& outputPath = "") : outputFile(outputPath), process(nullptr) {
        bpatch.setTrampRecursive(true);
        if (!outputFile.empty()) {
            output.open(outputFile);
        }
    }
    
    ~DynInstTracer() {
        if (output.is_open()) {
            output.close();
        }
    }
    
    bool attachToProcess(int pid) {
        process = bpatch.processAttach(nullptr, pid);
        if (!process) {
            std::cerr << "Failed to attach to process " << pid << std::endl;
            return false;
        }
        
        std::cout << "Successfully attached to process " << pid << std::endl;
        return true;
    }
    
    bool spawnProcess(const std::string& binary, const std::vector<std::string>& args) {
        // Convert args to char* array
        std::vector<const char*> argv;
        argv.push_back(binary.c_str());
        for (const auto& arg : args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);
        
        process = bpatch.processCreate(binary.c_str(), const_cast<const char**>(argv.data()));
        if (!process) {
            std::cerr << "Failed to spawn process: " << binary << std::endl;
            return false;
        }
        
        // Write spawn event
        if (output.is_open()) {
            output << "{"
                   << "\"ts\": " << getTimestamp() << ", "
                   << "\"kind\": \"process_spawn\", "
                   << "\"binary\": \"" << binary << "\", "
                   << "\"args\": [";
            for (size_t i = 0; i < args.size(); ++i) {
                if (i > 0) output << ", ";
                output << "\"" << args[i] << "\"";
            }
            output << "]}\n";
            output.flush();
        }
        
        std::cout << "Successfully spawned process: " << binary << std::endl;
        return true;
    }
    
    void instrumentInstructions(const std::vector<std::string>& functions) {
        if (!process) {
            std::cerr << "No process available for instrumentation" << std::endl;
            return;
        }
        
        // Get the application image
        BPatch_image* image = process->getImage();
        if (!image) {
            std::cerr << "Failed to get process image" << std::endl;
            return;
        }
        
        // Get all modules
        std::vector<BPatch_module*>* modules = image->getModules();
        
        for (auto module : *modules) {
            std::vector<BPatch_function*>* funcs = module->getProcedures();
            
            for (auto func : *funcs) {
                std::string funcName = func->getName();
                
                // Filter functions if specified
                if (!functions.empty()) {
                    bool found = false;
                    for (const auto& targetFunc : functions) {
                        if (funcName.find(targetFunc) != std::string::npos) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) continue;
                }
                
                // Get function's control flow graph
                BPatch_flowGraph* cfg = func->getCFG();
                if (!cfg) continue;
                
                std::set<BPatch_basicBlock*> blocks;
                cfg->getAllBasicBlocks(blocks);
                
                for (auto block : blocks) {
                    // Get instructions in this basic block
                    Offset blockOffset = block->getStartAddress();
                    Offset blockEnd = block->getEndAddress();
                    
                    // Decode instructions in the block
                    InstructionDecoder decoder(
                        reinterpret_cast<const unsigned char*>(blockOffset),
                        blockEnd - blockOffset,
                        Arch_x86_64
                    );
                    
                    const unsigned char* currentPtr = reinterpret_cast<const unsigned char*>(blockOffset);
                    const unsigned char* endPtr = reinterpret_cast<const unsigned char*>(blockEnd);
                    
                    while (currentPtr < endPtr) {
                        Instruction instr = decoder.decode(currentPtr);
                        if (!instr.isValid()) break;
                        
                        std::stringstream addrStream;
                        addrStream << "0x" << std::hex << reinterpret_cast<uintptr_t>(currentPtr);
                        
                        std::string mnemonic = instr.format();
                        
                        // Get raw instruction bytes
                        std::string bytesHex = bytesToHex(currentPtr, instr.size());
                        
                        // Get module name with buffer
                        char moduleNameBuf[256];
                        module->getName(moduleNameBuf, sizeof(moduleNameBuf));
                        
                        // Write instruction event
                        writeEvent("instruction", addrStream.str(), mnemonic, bytesHex, 
                                 instr.size(), funcName, moduleNameBuf);
                        
                        currentPtr += instr.size();
                    }
                }
            }
        }
        
        std::cout << "Instrumentation completed" << std::endl;
    }
    
    void run(double duration = 0.0) {
        if (!process) {
            std::cerr << "No process to run" << std::endl;
            return;
        }
        
        // Continue the process
        if (!process->continueExecution()) {
            std::cerr << "Failed to continue process execution" << std::endl;
            return;
        }
        
        // Wait for specified duration or until process terminates
        auto startTime = std::chrono::high_resolution_clock::now();
        
        while (true) {
            if (process->isTerminated()) {
                std::cout << "Process terminated" << std::endl;
                break;
            }
            
            if (duration > 0.0) {
                auto currentTime = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration<double>(currentTime - startTime).count();
                if (elapsed >= duration) {
                    std::cout << "Duration limit reached, terminating process" << std::endl;
                    process->terminateExecution();
                    break;
                }
            }
            
            // Small sleep to avoid busy waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    void detach() {
        if (process && !process->isTerminated()) {
            process->detach(true);
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <spawn|attach> <binary|pid> [args...] [--output file] [--duration seconds] [--functions func1,func2,...]" << std::endl;
        return 1;
    }
    
    std::string mode = argv[1];
    std::string target = argv[2];
    std::vector<std::string> args;
    std::string outputFile;
    double duration = 0.0;
    std::vector<std::string> functions;
    
    // Parse command line arguments
    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "--duration" && i + 1 < argc) {
            duration = std::stod(argv[++i]);
        } else if (arg == "--functions" && i + 1 < argc) {
            std::string funcList = argv[++i];
            std::stringstream ss(funcList);
            std::string func;
            while (std::getline(ss, func, ',')) {
                functions.push_back(func);
            }
        } else if (mode == "spawn") {
            args.push_back(arg);
        }
    }
    
    DynInstTracer tracer(outputFile);
    
    if (mode == "spawn") {
        if (!tracer.spawnProcess(target, args)) {
            return 1;
        }
    } else if (mode == "attach") {
        int pid = std::stoi(target);
        if (!tracer.attachToProcess(pid)) {
            return 1;
        }
    } else {
        std::cerr << "Invalid mode: " << mode << ". Use 'spawn' or 'attach'" << std::endl;
        return 1;
    }
    
    // Perform instrumentation
    tracer.instrumentInstructions(functions);
    
    // Run the process
    tracer.run(duration);
    
    // Clean up
    tracer.detach();
    
    return 0;
}