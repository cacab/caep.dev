package subject

import (
	"encoding/json"
	"fmt"
	"log"
)

// ParseSimpleSubject parses a JSON object into the appropriate simple subject type
func ParseSimpleSubject(data []byte) (SimpleSubject, error) {
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse subject: %w", err)
	}

	format := Format(raw["format"])
	switch format {
	case FormatEmail:
		var subject EmailSubject
		if err := json.Unmarshal(data, &subject); err != nil {
			return nil, err
		}

		return &subject, nil
	case FormatPhone:
		var subject PhoneSubject
		if err := json.Unmarshal(data, &subject); err != nil {
			return nil, err
		}

		return &subject, nil
	case FormatIssuerSub:
		var subject IssuerSubSubject
		if err := json.Unmarshal(data, &subject); err != nil {
			log.Printf("iss_sub decode error: %v", err)
			return nil, err
		}

		return &subject, nil
	case FormatURI:
		var subject URISubject
		if err := json.Unmarshal(data, &subject); err != nil {
			return nil, err
		}

		return &subject, nil
	case FormatOpaque:
		var subject OpaqueSubject
		if err := json.Unmarshal(data, &subject); err != nil {
			return nil, err
		}

		return &subject, nil
	default:
		return nil, NewError(ErrCodeInvalidFormat, "unsupported subject format", "format")
	}
}

func ParseComplexSubject(data []byte) (ComplexSubject, error) {
	var subject ComplexSubjectImpl
	if err := json.Unmarshal(data, &subject); err != nil {
		return nil, fmt.Errorf("failed to parse complex subject: %w", err)
	}

	return &subject, nil
}

func ParseSubject(data []byte) (Subject, error) {
	// First unmarshal just the format to determine the type
	var formatObj struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(data, &formatObj); err != nil {
		return nil, fmt.Errorf("failed to parse subject format: %w", err)
	}

	// Based on the format, parse as either simple or complex subject
	switch Format(formatObj.Format) {
	case FormatComplex:
		return ParseComplexSubject(data)
	case FormatEmail, FormatPhone, FormatIssuerSub, FormatURI, FormatOpaque:
		return ParseSimpleSubject(data)
	default:
		return nil, NewError(
			ErrCodeInvalidFormat,
			fmt.Sprintf("unsupported subject format: %s", formatObj.Format),
			"format",
		)
	}
}
