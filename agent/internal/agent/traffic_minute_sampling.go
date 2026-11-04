package agent

import (
	"errors"
	"strconv"
)

const maxTrafficMinuteSamples = 16_384

var errTrafficMinuteSampleLimit = errors.New("traffic minute sampling reached its local relationship or time bound")

type trafficMinuteBucket struct {
	minute int64
	ids    map[string]struct{}
}

// Keep the current event minute and its predecessor for overlapping drains.
// The stable event identity lets the controller also deduplicate after an agent
// restart or a retry that crossed the bucket boundary.
type trafficMinuteSampler struct {
	current  trafficMinuteBucket
	previous trafficMinuteBucket
}

func trafficSampleID(sessionID string, flow Flow) string {
	return shaText("prthak-traffic-minute-v1\x00" + sessionID + "\x00" + flow.SourceIP + "\x00" +
		strconv.Itoa(flow.Port) + "\x00" + flow.Protocol + "\x00" + strconv.FormatInt(flow.FirstSeen.Unix()/60, 10))
}

func (s *trafficMinuteSampler) reserve(sessionID string, flow Flow) (string, error) {
	minute := flow.FirstSeen.Unix() / 60
	if s.current.ids == nil || minute > s.current.minute {
		s.previous = trafficMinuteBucket{minute: minute - 1}
		if s.current.ids != nil && s.current.minute == minute-1 {
			s.previous = s.current
		}
		s.current = trafficMinuteBucket{minute: minute, ids: make(map[string]struct{})}
	}
	bucket := &s.current
	if minute == s.previous.minute {
		bucket = &s.previous
		if bucket.ids == nil {
			bucket.ids = make(map[string]struct{})
		}
	}
	if minute != bucket.minute {
		return "", errTrafficMinuteSampleLimit
	}
	id := trafficSampleID(sessionID, flow)
	if _, seen := bucket.ids[id]; seen {
		return "", nil
	}
	if len(bucket.ids) >= maxTrafficMinuteSamples {
		return "", errTrafficMinuteSampleLimit
	}
	bucket.ids[id] = struct{}{}
	return id, nil
}

func (s *trafficMinuteSampler) release(id string) {
	delete(s.current.ids, id)
	delete(s.previous.ids, id)
}
