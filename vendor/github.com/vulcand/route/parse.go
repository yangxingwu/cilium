package route

import (
	"fmt"

	"github.com/vulcand/predicate"
)

// IsValid checks whether expression is valid
func IsValid(expr string) bool {
	_, err := parse(expr, &match{})
	return err == nil
}

/*
// IsValid checks whether expression is valid
func IsKafkaValid(expr string) bool {
	_, err := parseKafka(expr, &match{})
	return err == nil
}

//Manali TODO new parser here for kafka.

func parseKafka(expression string, result *match) (matcher, error) {
	p, err := predicate.NewParser(predicate.Def{
		Functions: map[string]interface{}{
			"ApiVersion":       methodTrieMatcher,
			"ApiVersionRegexp": methodRegexpMatcher,

			"Topic":       methodTrieMatcher,
			"TopicRegexp": methodRegexpMatcher,

			"ApiKey":       methodTrieMatcher,
			"ApiKeyRegexp": methodRegexpMatcher,
		},
		Operators: predicate.Operators{
			AND: newAndMatcher,
		},
	})
	if err != nil {
		return nil, err
	}
	out, err := p.Parse(expression)
	if err != nil {
		return nil, err
	}
	m, ok := out.(matcher)
	if !ok {
		return nil, fmt.Errorf("unknown result type: %T", out)
	}
	m.setMatch(result)
	return m, nil
}
*/

func parse(expression string, result *match) (matcher, error) {
	p, err := predicate.NewParser(predicate.Def{
		Functions: map[string]interface{}{
			"Host":       hostTrieMatcher,
			"HostRegexp": hostRegexpMatcher,

			"Path":       pathTrieMatcher,
			"PathRegexp": pathRegexpMatcher,

			"Method":       methodTrieMatcher,
			"MethodRegexp": methodRegexpMatcher,

			"Header":       headerTrieMatcher,
			"HeaderRegexp": headerRegexpMatcher,
		},
		Operators: predicate.Operators{
			AND: newAndMatcher,
		},
	})
	if err != nil {
		return nil, err
	}
	out, err := p.Parse(expression)
	if err != nil {
		return nil, err
	}
	m, ok := out.(matcher)
	if !ok {
		return nil, fmt.Errorf("unknown result type: %T", out)
	}
	m.setMatch(result)
	return m, nil
}
