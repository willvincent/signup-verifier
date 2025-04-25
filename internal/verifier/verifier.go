package verifier

import "fmt"

type Verifier interface {
	Verify(email string) (bool, error)
}

type Factory func(apiKey string) Verifier

var registry = map[string]Factory{}

func Register(name string, factory Factory) {
	if _, exists := registry[name]; exists {
		panic("verifier " + name + " already registered")
	}
	registry[name] = factory
}

func NewFromProvider(name, apiKey string) (Verifier, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown verifier: %s", name)
	}
	return factory(apiKey), nil
}
