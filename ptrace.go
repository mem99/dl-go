package main

// ptrace.go: remote controls with ptrace

import (
    "fmt"

    "golang.org/x/sys/unix"
)

type PTraceTool struct {
    PID int
}

func RunPtrace(pid int) (pt PTraceTool) {
    pt.PID = pid

    return
}

func (self PTraceTool) attach() bool {
    err := unix.PtraceAttach(self.PID)
    if err != nil {
        fmt.Println("[!] Attach error:", err)
        return false
    }

    return self.Wait4Process(unix.WUNTRACED).Stopped()
}

func (self PTraceTool) detach() {
    err := unix.PtraceDetach(self.PID)
    if err != nil {
        fmt.Println("[!] Detach error:", err)
    }
}

func (self PTraceTool) Wait4Process (options int) (wstatus unix.WaitStatus) {
    cid, err := unix.Wait4(self.PID, &wstatus, options, nil)

    if cid != self.PID {
        fmt.Println("[!] Wait did not stop as expected: cid", cid, ", expected", self.PID)
    }
    if err != nil {
        fmt.Println("[!] Wait error:", err)
    }

    return
}

func (self PTraceTool) Wait4Trap() unix.Signal {
    wstatus := self.Wait4Process(unix.WUNTRACED)

    return wstatus.StopSignal()
}

func (self PTraceTool) StepOnce() bool {
    err := unix.PtraceSingleStep(self.PID)
    if err != nil {
        fmt.Println("[!] Problem stepping:", err)
        return false
    }

    return self.Wait4Process(unix.WUNTRACED).Stopped()
}

func (self PTraceTool) Continue() {
    err := unix.PtraceCont(self.PID, 0)
    if err != nil {
        fmt.Println("[!] Problem continuing:", err)
    }
}

func (self PTraceTool) GetRegs() (p unix.PtraceRegs) {
    err := unix.PtraceGetRegs(self.PID, &p)
    if err != nil {
        fmt.Println("[!] GetRegs error:", err)
    }

    return
}

func (self PTraceTool) SetRegs(p *unix.PtraceRegs) {
    err := unix.PtraceSetRegs(self.PID, p)
    if err != nil {
        fmt.Println("[!] SetRegs error:", err)
    }
}

func (self PTraceTool) ReadData(addr uintptr, size int) (data []byte, success bool) {
    data = make([]byte, size)
    local := make([]unix.Iovec, 1)
    remote := make([]unix.RemoteIovec, 1)

    local[0].Base = &data[0]
    local[0].Len = uint64(size)
    remote[0].Base = addr
    remote[0].Len = size

    n, err := unix.ProcessVMReadv(self.PID, local, remote, 0)
    if err != nil {
        fmt.Println("[!] ProcessVmReadv error:", err)
        return nil, false
    }

    return data, n == size
}

func (self PTraceTool) WriteVMDataV(addr uintptr, data *byte, len uint64) bool {
    local := []unix.Iovec{}
    remote := []unix.RemoteIovec{}

    local[0].Base = data
    local[0].Len = len
    remote[0].Base = addr
    remote[0].Len = int(len)

    n, err := unix.ProcessVMWritev(self.PID, local, remote, 0)
    if err != nil {
        fmt.Println("[!] ProcessVmWritev error:", err)
        return false
    }

    return uint64(n) == len
}

func (self PTraceTool) WriteData(addr uintptr, b *[]byte) bool {
    n, err := unix.PtracePokeText(self.PID, addr, *b)
    if err != nil {
        fmt.Println("[!] PokeText error:", err)
        return false
    }

    return n != -1
}
