/**
 * @file memcheck.cpp
 * @brief This file contains the memcheck class for analyzing LLVM functions.
 */
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Analysis/LoopInfo.h"
#include <llvm/Demangle/Demangle.h>

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>

using namespace llvm;

namespace {
  /**
   * @brief Pass for static function analysis.
   */
  class memcheck : public PassInfoMixin<memcheck> {
  private:
    /**
     * @brief Struct to store analysis results for a function.
     */
    struct FunctionAnalysis {
      std::string mangledName;    /* Mangled function name */
      std::string demangledName;  /* Demangled function name */
      size_t loads = 0;           /* Loads */
      size_t stores = 0;          /* Stores */
      size_t bytes = 0;           /* Bytes */
    };

    std::set<const Function *> visitedFunctions;
    
    // Output files names
    std::string csvFileName = "static_function_analysis.csv";
    std::string jsonFileName = "static_function_analysis.json";

    /**
     * @brief Analyze a function and compute its metrics.
     * @param F The LLVM function to analyze.
     * @return A FunctionAnalysis struct containing the analysis results.
     */
    FunctionAnalysis analyzeFunction(Function &F, std::map<Function *, FunctionAnalysis> &analysisMap) {
      /* Check if the function has already been analyzed */
      auto it = analysisMap.find(&F);
      if (it != analysisMap.end()) {
        /* If the function has already been analyzed, return the stored results */
        return it->second;
      }

      FunctionAnalysis result;
      result.mangledName = F.getName().str();
      result.demangledName = demangle(result.mangledName);

      for (auto &BB : F) {
        for (auto &I : BB) {
          /* Check if the instruction is a load */
          if (auto *load = dyn_cast<LoadInst>(&I)) {
            result.loads++;
            result.bytes += F.getParent()->getDataLayout().getTypeAllocSize(load->getType());
          }
          /* Check if the instruction is a store */
          else if (auto *store = dyn_cast<StoreInst>(&I)) {
            result.stores++;
            result.bytes += F.getParent()->getDataLayout().getTypeAllocSize(store->getValueOperand()->getType());
          }
        }
      }
      /* Store the analysis results in the map */
      analysisMap[&F] = result;

      return result;
    }

    /**
     * @brief Determines if a function is user-defined based on its file path.
     *
     * This function checks whether the given LLVM function is user-defined by examining the debug
     * information associated with the function. If the function's source file path starts with the
     * specified project root path, it is considered user-defined.
     * 
     * @param F A reference to the LLVM function to be checked.
     * @return true if the function is user-defined, false otherwise.
     *
     * @note This function relies on the presence of debug information in the LLVM IR. If the debug
     *       information is missing or if the function's source file is not within the project root
     *       directory, the function will be considered not user-defined.
     */
    bool isUserDefinedFunction( const Function &F ) {
      /* Retrieve the project root path from the $SCOP_ROOT environment variable */
      const char* projectRoot = std::getenv("SCOP_ROOT");
      /* If the $SCOP_ROOT environment variable is not set, return false */
      if (!projectRoot) {
        errs() << "Error: $SCOP_ROOT environment variable is not set.\n";
        return false;
      }

      /* Check if the function has debug information */
      if (const DISubprogram *subprog = F.getSubprogram()) {
        /* Get the file where the function is defined */
        const DIFile *file = subprog->getFile();

        if (file) {
          /* Get the directory and file path */
          std::string dir = file->getDirectory().str();
          std::string filePath = file->getFilename().str();

          /* Construct the full path to the file */
          llvm::SmallString<256> fullPath(dir);
          llvm::sys::path::append(fullPath, filePath); // Corrected namespace

          /* Check if the full path starts with the project root */
          return fullPath.str().startswith(projectRoot);
        }
      }

      /* If there's no debug information, or the file is not within the project root,
        assume it's not a user-defined function */
      return false;
    }

    /**
     * @brief Print the analysis results to standard error.
     * @param F The LLVM function being analyzed.
     * @param analysis The analysis results for the function.
     */
    void printFunctionAnalysis(const Function &F, const FunctionAnalysis &analysis) {
      errs() << "-------------------------------------------\n";
      errs() << " Function Name (Demangled): " << analysis.demangledName << "\n";
      errs() << " Function Name (Mangled): " << analysis.mangledName << "\n;";
      errs() << "-------------------------------------------\n";
      errs() << "  'Loads': " << analysis.loads << "\n";
      errs() << "  'Stores': " << analysis.stores << "\n";
      errs() << "  'Bytes': " << analysis.bytes << "\n";
      errs() << "-------------------------------------------\n"; 
      errs() << "\n";
    }

    /**
     * @brief Escape a cell for CSV formatting.
     * @param cell The cell content to escape.
     * @return The escaped cell.
     */
    std::string escapeCSV(const std::string &cell) {
      std::string escaped = cell;
      if (escaped.find(',') != std::string::npos || escaped.find('\"') != std::string::npos) {
        /* Replace all " with "" */
        size_t pos = 0;
        while ((pos = escaped.find('\"', pos)) != std::string::npos) {
          escaped.replace(pos, 1, "\"\"");
          pos += 2;
        }
        /* Wrap the cell in " */
        escaped = "\"" + escaped + "\"";
      }
      return escaped;
    }

    /**
     * @brief Write the analysis results to a CSV file.
     * @param F The LLVM function being analyzed.
     * @param analysis The analysis results for the function.
     * @param csvFileName The name of the CSV file.
     */
    void writeToCSV(const Function &F, const FunctionAnalysis &analysis, const std::string &csvFileName) {
      static std::ofstream csvFile;
      static bool isFileInitialized = false;
      if (!isFileInitialized) {
        /* Open the CSV file and write headers */
        csvFile.open(csvFileName);
        csvFile << "'Function Name (Demangled)','Function Name (Mangled)','Loads','Stores','Bytes' \n";
        isFileInitialized = true;
      }
      /* Write the function analysis data to the CSV file */
      csvFile << escapeCSV(analysis.demangledName) << ','
              << escapeCSV(analysis.mangledName) << ','
              << analysis.loads << ','
              << analysis.stores << ','
              << analysis.bytes << '\n';
    }

    /**
     * @brief Write the analysis results to a JSON file.
     * @param analysis The analysis results for the function.
     * @param functionName The name of the function.
     * @param jsonFile The JSON file stream.
     * @param isFirstFunction Indicates if this is the first function being written.
     */
    void writeToJSON(const FunctionAnalysis &analysis, const std::string &functionName, std::ofstream &jsonFile, bool isFirstFunction) {
      if (!isFirstFunction) {
        jsonFile << ",\n";  /* Append a comma and newline for subsequent JSON objects */
      }

      /* Construct the JSON string */
      std::stringstream jsonStream;
      jsonStream << "  {\n";
      jsonStream << "    \"Function Name (Demangled)\": \"" << analysis.demangledName << "\",\n";
      jsonStream << "    \"Function Name (Mangled)\": \"" << analysis.mangledName << "\",\n";
      jsonStream << "    \"Loads\": " << analysis.loads << ",\n";
      jsonStream << "    \"Stores\": " << analysis.stores << ",\n";
      jsonStream << "    \"Bytes\": " << analysis.bytes << "\n";
      jsonStream << "  }";

      /* Write the JSON string to the file */
      jsonFile << jsonStream.str();
    }

  public:
    /**
     * @brief Run the analysis for each function in the module.
     * @param M The LLVM module to analyze.
     * @param MAM The ModuleAnalysisManager.
     * @return A PreservedAnalyses object.
     */
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
      /* Map to store the number of times each function is called */
      std::map<Function *, int> callCounts;

      /* Iterate over all functions in the module */
      for (Function &F : M) {
        /* Iterate over all basic blocks in the function */
        for (BasicBlock &BB : F) {
          /* Iterate over all instructions in the basic block */
          for (Instruction &I : BB) {
            /* If the instruction is a call instruction, increment the call count */
            if (CallInst *callInst = dyn_cast<CallInst>(&I)) {
              /* If the called function is defined in the user's source files */
              if (Function *calledFunction = callInst->getCalledFunction()) {
                callCounts[calledFunction]++;
              }
            }
          }
        }
      }

      /* Open the json file at the beginning */
      std::ofstream jsonFile(jsonFileName);
      jsonFile << "[\n"; // Write opening bracket
      bool isFirstFunction = true;
      for (Function &F : M) {
        ////////////////////////////////////////////////////////////
        if (isUserDefinedFunction(F) && !F.isDeclaration()) {
        // if (isUserDefinedFunction(F) && !F.isDeclaration() && F.getName() != "main") {
        ////////////////////////////////////////////////////////////
          /* Clear the visited functions set */
          visitedFunctions.clear();
          /* Analyze the function */
          std::map<Function *, FunctionAnalysis> analysisMap;
          FunctionAnalysis analysis = analyzeFunction(F, analysisMap);
          /* Print the analysis to errs() */
          printFunctionAnalysis(F, analysis);
          /* Write the analysis to a CSV file */
          writeToCSV(F, analysis, csvFileName);
          /* Write the analysis to a JSON file */
          writeToJSON(analysis, F.getName().str(), jsonFile, isFirstFunction);
          /* Close the top bracket of the JSON file */
          isFirstFunction = false;
        }
      }
      jsonFile << "\n]"; /* Write closing bracket at the end */
      jsonFile.close();

      return PreservedAnalyses::all();
    }
  };
} /* end of anonymous namespace */


/**
 * This is the core interface for pass plugins. It guarantees that
 * the same version of the plugin is used throughout the LLVM
 * invocation process.
 */
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "memcheck", LLVM_VERSION_STRING,
    [](llvm::PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](llvm::StringRef Name, llvm::ModulePassManager &MPM,
            llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
          if (Name == "memcheck") {
            MPM.addPass(memcheck());
            return true;
          }
          return false;
        }
      );
    }
  };
}
