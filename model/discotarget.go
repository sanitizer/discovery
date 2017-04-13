package discomodel

import "fmt"

type DiscoveredTarget struct {
	Id    int
	Ip    string
	Port  int
	Alias string
	Status string
}

func (this DiscoveredTarget) String() string {
	return fmt.Sprintf("\n==== Discovered Target Info ====\nId:\t%d\nIP address:\t%q\nPort:\t%d\nAlias:\t%q\nStatus: %q\n",
		this.Id,
		this.Ip,
		this.Port,
		this.Alias,
		this.Status)
}
