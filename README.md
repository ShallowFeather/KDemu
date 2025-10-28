# KDemu

A hybrid semi-emulated, semi-native Windows kernel driver emulator designed for advanced rootkit and anti-cheat analysis, addressing the limitations of existing emulation solutions.

## Conference
This project have been accept by CODEBLUE 2025

[Bypassing Anti-Debugging: A Hybrid Real-Simulated Approach to Rootkit Analysis
]("https://codeblue.jp/en/program/time-table/day2-t2-01/)

## Architecture

KDemu's hybrid architecture consists of:

- **Emulation Engine** (`Emulate.cpp/hpp`): kernel API implementations with intelligent hook management
- **PE Loader** (`LoadPE.cpp/hpp`): Advanced PE parsing with kernel dump integration and driver overwriting
- **Kernel Dump Manager**: Real-time kernel memory dump analysis and parameter extraction
- **SEH Handler**: Native Windows exception handling using InvertedFunctionTableList
- **Multithreading Engine**: Parallel execution with memory locking and context management
- **Anti-Detection Layer**: MSR handling, hypervisor evasion, and detection countermeasures
- **Monitoring System**: Object access tracking and register operation logging

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd KDemu
   ```

2. **Install dependencies via vcpkg**:
   ```bash
   vcpkg install unicorn capstone
   ```

3. **Build the project**:
   - Open `KDemu.sln` in Visual Studio
   - Select Release configuration (x64)
   - Build the solution

4. **Download Memory Dump**:
   https://drive.google.com/file/d/1MDZ2s7RLGvypC0FDS6MOYgMglTyU6O9n/view?usp=sharing
   
   Put it into the KDemu folder

## Usage

### Prerequisites Setup

1. **Kernel Memory Dump**: Obtain a Windows kernel memory dump (`mem.dmp`) captured at a driver entry breakpoint
> if you use another kernel dump, you have to change some of the parmenter like some of base addr..register..etc
2. **Target Driver**: Place the driver you want to analyze in the project directory

### Debugging
Enable GDB server support by uncommenting the `gdbServer()` call in `mainThread()`.

## Project Structure

```
KDemu/
├── KDemu/
│   ├── KDemu.cpp           # Main entry point
│   ├── Emulate.cpp/hpp     # API emulation engine
│   ├── LoadPE.cpp/hpp      # PE loader and memory management
│   ├── UnicornEmu.hpp      # Unicorn engine wrapper
│   ├── Global.h            # Common definitions
│   ├── NtType.hpp          # Windows type definitions
│   ├── include/            # Third-party headers
│   └── lib/                # Static libraries
├── vcpkg.json              # Package dependencies
└── KDemu.sln              # Visual Studio solution
```

## Author
ShallowFeather & HeroBurger

## Acknowledgments

### Core Technologies
- [Unicorn Engine](https://www.unicorn-engine.org/) - CPU emulation framework
- [Capstone](https://www.capstone-engine.org/) - Disassembly engine  
- [LIEF](https://lief.quarkslab.com/) - Binary analysis library (contributed bug fix)
- [kdmp-parser](https://github.com/0vercl0k/kdmp-parser) - Kernel dump parsing

### Research References
- [**KACE (Kernel AntiCheat Emulator)**]("https://github.com/waryas/KACE") - Inspiration for user-mode to kernel-mode mapping
- [**What The Fuzz**]("https://github.com/0vercl0k/wtf) - Kernel dump utilization concepts
- **Speakeasy & Qiling** - Object monitoring and API emulation approaches
