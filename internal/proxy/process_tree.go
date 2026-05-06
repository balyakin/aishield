package proxy

import (
	"os/exec"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Command string `json:"command"`
}

func SnapshotProcessTree(rootPID int) []ProcessInfo {
	processes, err := listProcesses()
	if err != nil {
		return []ProcessInfo{{PID: rootPID}}
	}

	childrenByParent := make(map[int][]ProcessInfo)
	for _, process := range processes {
		childrenByParent[process.PPID] = append(childrenByParent[process.PPID], process)
	}

	snapshot := make([]ProcessInfo, 0)
	queue := []int{rootPID}
	for len(queue) > 0 {
		currentPID := queue[0]
		queue = queue[1:]
		for _, process := range processes {
			if process.PID == currentPID {
				snapshot = append(snapshot, process)
				break
			}
		}
		for _, child := range childrenByParent[currentPID] {
			queue = append(queue, child.PID)
		}
	}

	if len(snapshot) == 0 {
		return []ProcessInfo{{PID: rootPID}}
	}
	return snapshot
}

func listProcesses() ([]ProcessInfo, error) {
	output, err := exec.Command("ps", "-axo", "pid=,ppid=,comm=").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	processes := make([]ProcessInfo, 0, len(lines))
	for _, line := range lines {
		process, ok := parseProcessLine(line)
		if ok {
			processes = append(processes, process)
		}
	}
	return processes, nil
}

func parseProcessLine(line string) (ProcessInfo, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ProcessInfo{}, false
	}

	processID, err := strconv.Atoi(fields[0])
	if err != nil {
		return ProcessInfo{}, false
	}
	parentID, err := strconv.Atoi(fields[1])
	if err != nil {
		return ProcessInfo{}, false
	}

	return ProcessInfo{
		PID:     processID,
		PPID:    parentID,
		Command: strings.Join(fields[2:], " "),
	}, true
}
