package http_transformer

// ResponseBodyTranformer is an interface that allows different
// preparations to happen on the body of the message before
// it is sent (STORED AS A SINGLETON)
type ResponseBodyTransformer interface {
	Transform(*[]byte) (*[]byte, error)
}

var transformers = map[string]ResponseBodyTransformer{}

func init() {
	Register("noop", NoopTransformer{})
}

func Register(name string, transformer ResponseBodyTransformer) {
	transformers[name] = transformer
}

func GetResponseBodyTransformer(name string) ResponseBodyTransformer {
	if name == "" {
		// noop is the default transformer
		name = "noop"
	}

	return transformers[name]
}

type NoopTransformer struct{}

func (t NoopTransformer) Transform(body *[]byte) (*[]byte, error) {
	return body, nil
}
