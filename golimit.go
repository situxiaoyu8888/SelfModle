package SelfModle

type ChanType struct {
	ChanNum int
	Channel chan struct{}
}

func NewChannel(Num int) *ChanType {
	return &ChanType{
		ChanNum: Num,
		Channel: make(chan struct{}, Num),
	}
}

func (Group *ChanType) Run(F func()) {
	Group.Channel <- struct{}{}
	go func() {
		F()
		<-Group.Channel
	}()
}
