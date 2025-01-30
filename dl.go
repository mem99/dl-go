package main

// library injector

import (
    "fmt"
    "flag"
    "os"
    "debug/elf"
    "path/filepath"
)

var inputSO string

func main() {
    inputPID := flag.Int("pid", 0, "target process id")
    flag.StringVar(&inputSO, "so", "", "shared object")

    flag.Parse();

    if len(os.Args) == 1 {
        flag.Usage()
        return
    }

    if *inputPID == 0 {
        fmt.Println("pid cannot be null")
        return
    }

    process := OpenProcess(*inputPID)

    if err := process.IsAlive(); err != nil {
        fmt.Println("pid error:", err)
        return
    }

    if inputSO == "" {
        fmt.Println("object cannot be null")
        return
    }

    if _, err := os.Stat(inputSO); err != nil {
        fmt.Println("so error:", err)
        return
    }

    if inputSO[0] != '/' {
        inputSO, _ = filepath.Abs(inputSO)
    }

    // TODO: update tty write time

    if so_elf, err := elf.Open(inputSO); true {
        if err != nil {
            fmt.Println("so error:", err)
            return
        }
        is32 := process.Is386()
        if is32 && so_elf.Class != elf.ELFCLASS32 {
            fmt.Println("[!] Process is x32, shared object is", so_elf.Class.String())
            return
        } else if !is32 && so_elf.Class != elf.ELFCLASS64 {
            fmt.Println("[!] Process is x64, shared object is", so_elf.Class.String())
            return
        }
    }

    pt := RunPtrace(process.PID)

    sections := process.InitSections()
    if process.FindModule(&sections, inputSO) != nil {
        fmt.Printf("[!] Already loaded, remove? y/n/e (y): ")
        var in string
        fmt.Scanf("%s", &in)
        if len(in) == 0 || in[0] == 'y' {
            if pt.LoadLibrary(&process, &sections, true) == 0 {
                fmt.Println("[:(] Operation failed")
            }
            return
        } else if in[0] == 'e' {
            return
        }
    }

    if pt.LoadLibrary(&process, &sections, false) == 0 {
        fmt.Println("[:(] Operation failed")
    }

}

// load code

// parse an ELF file for a symbol's offset
func GetSymbolOffset(symbols *[]elf.Symbol, symbol string) uintptr {
    for i := range *symbols {
        if (*symbols)[i].Name == symbol {
            return uintptr((*symbols)[i].Value)
        }
    }

    return 0
}

func GetSymbols(library string) (s []elf.Symbol) {
    lib, err := elf.Open(library)
    if err != nil {
        fmt.Println("elf error:", err)
        panic("error finding offset")
    }
    defer lib.Close()

    s, _ = lib.DynamicSymbols()
    return
}

func (pt PTraceTool) LoadLibrary(process *Process, sections *[]ProcMapSection, unload bool) uint64 {
    // Get address of dlopen inside target process
    is32 := process.Is386()

    var libcPath string;
    if is32 {
        libcPath = "/usr/lib/libc.so.6"
    } else {
        libcPath = "/usr/lib64/libc.so.6"
    }

    libc := process.FindModule(sections, libcPath);
    if libc == nil {
        fmt.Println("[!] Couldn't find libc.so.6")
        return 0
    }

    symbols := GetSymbols(libcPath)

    dlopen_addr := GetSymbolOffset(&symbols, "dlopen")
    if dlopen_addr == 0 {
        fmt.Println("[!] Couldn't find dlopen")
        return 0
    }

    var dlclose_addr uintptr
    if unload == true {
        dlclose_addr = GetSymbolOffset(&symbols, "dlclose")
    }

    dlopen_addr = libc.Start + dlopen_addr
    dlclose_addr = libc.Start + dlclose_addr
//     fmt.Printf("[*] Found dlopen address: 0x%x\n", dlopen_addr)

    // Calculate size of the data to write to the section
    buffer_size := len(inputSO) + 1/*nt*/ + 32/*padding*/

    // Find a section for reading/writing/executing code
    // (Ptrace can write to non-writable regions)
    execSec, idx := process.NextSectionWithPerms(sections, Read | Execute | Private, 0)
    for execSec.Size < uint64(buffer_size) && execSec.Pathname != "[heap]" && idx < len(*sections) {
        execSec, idx = process.NextSectionWithPerms(sections, Read | Execute | Private, idx)
    }
    if idx == len(*sections) {
        fmt.Println("[!] Couldn't find execution space!")
        return 0
    }

    // Use end of section so we don't overwrite important code
    exec_addr := execSec.End - uintptr(buffer_size) - 32

    fmt.Printf("[*] Found execution space: 0x%x in %q\n", exec_addr, execSec.Pathname)

    if pt.attach() {
        defer pt.detach()

	// make sure it stops on syscall poll() since it seems to be the safest place to run things from
	// GDB also has similar behavior
	regs := pt.GetRegs()
        for {
	    if regs.Orig_rax == 7/*SYS_POLL*/ {
		break
	    }
	    pt.StepOnce()
	    pt.Wait4Trap()
	    regs = pt.GetRegs()
        }

        if curSec := process.FindSectionByAddress(sections, uintptr(regs.Rip)); curSec != nil {
            fmt.Printf("[*] Attached in %q\n", curSec.Pathname)
        }

        regs_backup := regs
        defer pt.SetRegs(&regs_backup)

        code_backup, success := pt.ReadData(exec_addr, buffer_size)
        if success == false {
            return 0
        }
        defer pt.WriteData(exec_addr, &code_backup)

        shellcode := []byte{0xff, 0xd0, 0xcc, 0xc3, 0x90, 0x90}
        if is32 {
            shellcode = append([]byte{0x56, 0x57}, shellcode...) // push esi, edi before call
        }
        b := shellcode
        b = append(b, inputSO...)
        b = append(b, 0) // term

        if len(b) > buffer_size {
            panic ("byte array is larger than max size...")
        }

        success = pt.WriteData(exec_addr, &b)
        if success == false {
            return 0
        }

        regs.Rip = uint64(exec_addr)
        regs.Rax = uint64(dlopen_addr)
        regs.Rdi = uint64(exec_addr) + uint64(len(shellcode))
        regs.Rsi = 2 /* RTLD_NOW */
        if is32 {
	    regs.Rbx = regs.Rdi
	    regs.Rcx = regs.Rsi
	}

        pt.SetRegs(&regs)

        pt.Continue()
        signal := pt.Wait4Trap() // wait for the interrupt

        if signal == 5/*SIGTRAP*/ {
            regs = pt.GetRegs()
            if regs.Rax != 0 {
                if unload {
                    handle := regs.Rax
                    for i := 1; i <= 2; i++ { // FIXME we are assuming there's only two handle references
                        regs.Rip = uint64(exec_addr)
                        regs.Rax = uint64(dlclose_addr)
                        regs.Rdi = handle
                        pt.SetRegs(&regs)
                        pt.Continue()
                        signal = pt.Wait4Trap()
                        if signal == 5 {
                            if i == 2 {
                                fmt.Println("[+] Library removed");
                            }
                        } else {
                            fmt.Printf("[!] Iteration %d failed\n", i);
                            // TODO run dlerror
                        }
                    }
                    return regs.Rax
                } else {
                    fmt.Printf("[+] Library loaded with handle 0x%x\n", regs.Rax)
                }
            } else {
                fmt.Println("[!] Stop received, but %%rax unused")
                return 0
            }
        } else {
            fmt.Println("[!] Process did not stop as expected:", signal)
            // TODO run dlerror
            return 0
        }

        return regs.Rax
    }

    return 0
}
