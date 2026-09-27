package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/cns"
	"github.com/metacubex/mihomo/log"
)

type CnsOption struct {
	BaseOption
	Key      string `inbound:"key,omitempty"`
	Password string `inbound:"password,omitempty"`
	Flag     string `inbound:"flag,omitempty"`
	UDP      bool   `inbound:"udp,omitempty"`
}

func (o CnsOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Cns struct {
	*Base
	config *CnsOption
	l      []*cns.Listener
}

func NewCns(options *CnsOption) (*Cns, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Cns{
		Base:   base,
		config: options,
	}, nil
}

func (c *Cns) Config() C.InboundConfig {
	return c.config
}

func (c *Cns) Address() string {
	var addrList []string
	for _, l := range c.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

func (c *Cns) Listen(tunnel C.Tunnel) error {
	lc := c.ListenConfig()
	for _, addr := range strings.Split(c.RawAddress(), ",") {
		l, err := cns.New(cns.Config{
			Listen:   addr,
			Key:      c.config.Key,
			Password: c.config.Password,
			Flag:     c.config.Flag,
			UDP:      c.config.UDP,
		}, lc, tunnel, c.Additions()...)
		if err != nil {
			return err
		}
		c.l = append(c.l, l)
	}
	log.Infoln("CNS[%s] proxy listening at: %s", c.Name(), c.Address())
	return nil
}

func (c *Cns) Close() error {
	var errs []error
	for _, l := range c.l {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close tcp listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*Cns)(nil)
