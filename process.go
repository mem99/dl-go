package main

// process.go: returns process information

import (
    "os"
    "strings"
    "strconv"
    "bufio"

    "golang.org/x/sys/unix"
)

type perm uint8

const (
    Read perm = 1 << iota
    Write
    Execute
    Private
    Shared
)

type ProcMapSection struct {
    Start uintptr
    End uintptr
    Size uint64
    Perms perm
    INode uint64
    Pathname string
}

type Process struct {
    PID int;
}

func OpenProcess(process_id int) (p Process) {
    p.PID = process_id

    return
}

func (self Process) IsAlive() error {
    return unix.Kill(self.PID, 0)
}

func (self Process) Is386() bool {
    auxvFile, err := os.ReadFile("/proc/" + strconv.FormatInt(int64(self.PID), 10) + "/auxv")
    if err != nil {
        panic ("cannot open auxv")
    }

    if auxvFile[4] != 0 || auxvFile[5] != 0 || auxvFile[6] != 0 || auxvFile[7] != 0 {
        return true
    }

    return false
}

/*****************************************************************
 * Sections
 ****************************************************************/
func (self Process) InitSections() []ProcMapSection {
    mapsFile, err := os.Open("/proc/" + strconv.FormatInt(int64(self.PID), 10) + "/maps")
    if err != nil {
        panic ("cannot open maps")
    }
    defer mapsFile.Close()

    maps := make([]ProcMapSection, 0)
    scanner := bufio.NewScanner(mapsFile)

    for scanner.Scan() {
        fields := strings.Fields(scanner.Text())
        split := strings.Split(fields[0], "-")

        start, _ := strconv.ParseUint(split[0], 16, 0)
        end, _ := strconv.ParseUint(split[1], 16, 0)

        perms := perm(0)
        for _, c := range fields[1] {
            switch c {
                case 'r': perms |= Read
                case 'w': perms |= Write
                case 'x': perms |= Execute
                case 'p': perms |= Private
                case 's': perms |= Shared
            }
        }

        inode, _ := strconv.ParseUint(fields[4], 10, 0)

        path := ""
        if len(fields) == 5 {
            path = "[anon]"
        } else {
            path = strings.Join(fields[5:], " ")
        }

        maps = append(maps, ProcMapSection{ uintptr(start), uintptr(end), end - start, perms, inode, path })
    }

    return maps
}

func (self Process) FindModule(s *[]ProcMapSection, module string) *ProcMapSection {
    // Avoid copying values
    for i := range *s {
        if strings.Contains((*s)[i].Pathname, module) {
            return &(*s)[i]
        }
    }
    // TODO find all respective sections, return as slice

    return nil
}

func (self Process) NextSectionWithPerms(s *[]ProcMapSection, pm perm, i int) (*ProcMapSection, int) {
    for ; i < len(*s); i++ {
        if (*s)[i].Perms & pm == pm {
            return &(*s)[i], i + 1
        }
    }

    return nil, i
}

func (self Process) FindSectionByAddress(s *[]ProcMapSection, address uintptr) *ProcMapSection {
    lo := 0
    hi := len(*s) - 1

    for lo <= hi {
        i := lo + ((hi - lo) >> 1)

        if address > (*s)[i].End {
            lo = i + 1
        } else if address < (*s)[i].Start {
            hi = i - 1
        } else {
            return &(*s)[i]
        }
    }

    return nil
}
