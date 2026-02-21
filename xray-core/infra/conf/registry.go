package conf

// Creator creates a config instance
type Creator func() interface{}

var inboundConfigCreators = map[string]Creator{}

// RegisterConfigCreator registers a protocol config creator
func RegisterConfigCreator(name string, creator Creator) {
	inboundConfigCreators[name] = creator
}

// GetConfigCreator returns creator by name
func GetConfigCreator(name string) (Creator, bool) {
	c, ok := inboundConfigCreators[name]
	return c, ok
}
