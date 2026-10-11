package fuzzysearch

import (
	"sort"
	"strings"
	"unicode"
)

// Record is a dictionary entry. Identifier is kept opaque so that search never
// rewrites a registered CPE or PURL.
type Record struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
	Vendor     string `json:"vendor,omitempty"`
	Ecosystem  string `json:"ecosystem,omitempty"`
}

type Result struct {
	Record
	TrigramSimilarity float64 `json:"trigram_similarity"`
	EditDistance      int     `json:"edit_distance"`
	EditSimilarity    float64 `json:"edit_similarity"`
	RankScore         float64 `json:"rank_score"`
}

type Options struct {
	Query     string
	Vendor    string
	Ecosystem string
	Limit     int
}

// Search normalizes names for retrieval, computes Dice trigram similarity and
// rune-based Levenshtein distance, then returns a stable ranked list.
func Search(records []Record, opts Options) []Result {
	query := normalize(opts.Query)
	if query == "" {
		return []Result{}
	}
	if opts.Limit <= 0 || opts.Limit > 100 {
		opts.Limit = 20
	}
	vendor := normalize(opts.Vendor)
	ecosystem := normalize(opts.Ecosystem)
	results := make([]Result, 0, len(records))
	for _, record := range records {
		if vendor != "" && normalize(record.Vendor) != vendor {
			continue
		}
		if ecosystem != "" && normalize(record.Ecosystem) != ecosystem {
			continue
		}
		name := normalize(record.Name)
		if name == "" {
			continue
		}
		distance := levenshtein([]rune(query), []rune(name))
		maxLen := max(runeLength(query), runeLength(name))
		editSimilarity := 1.0
		if maxLen > 0 {
			editSimilarity = 1 - float64(distance)/float64(maxLen)
		}
		trigram := diceSimilarity(query, name)
		results = append(results, Result{
			Record: record, TrigramSimilarity: trigram,
			EditDistance: distance, EditSimilarity: editSimilarity,
			RankScore: 0.5*trigram + 0.5*editSimilarity,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RankScore != results[j].RankScore {
			return results[i].RankScore > results[j].RankScore
		}
		if results[i].TrigramSimilarity != results[j].TrigramSimilarity {
			return results[i].TrigramSimilarity > results[j].TrigramSimilarity
		}
		if results[i].EditDistance != results[j].EditDistance {
			return results[i].EditDistance < results[j].EditDistance
		}
		return results[i].ID < results[j].ID
	})
	if len(results) > opts.Limit {
		results = results[:opts.Limit]
	}
	return results
}

func normalize(value string) string {
	value = strings.TrimFunc(value, unicode.IsSpace)
	return strings.ToLower(value)
}

func runeLength(value string) int { return len([]rune(value)) }

func trigrams(value string) map[string]struct{} {
	runes := []rune("  " + value + " ")
	grams := make(map[string]struct{}, max(0, len(runes)-2))
	for i := 0; i+2 < len(runes); i++ {
		grams[string(runes[i:i+3])] = struct{}{}
	}
	return grams
}

func diceSimilarity(a, b string) float64 {
	left, right := trigrams(a), trigrams(b)
	if len(left)+len(right) == 0 {
		return 1
	}
	intersection := 0
	for gram := range left {
		if _, ok := right[gram]; ok {
			intersection++
		}
	}
	return 2 * float64(intersection) / float64(len(left)+len(right))
}

func levenshtein(a, b []rune) int {
	if len(a) > len(b) {
		a, b = b, a
	}
	previous := make([]int, len(a)+1)
	current := make([]int, len(a)+1)
	for i := range previous {
		previous[i] = i
	}
	for row, right := range b {
		current[0] = row + 1
		for column, left := range a {
			cost := 0
			if left != right {
				cost = 1
			}
			current[column+1] = min(
				current[column]+1,
				previous[column+1]+1,
				previous[column]+cost,
			)
		}
		previous, current = current, previous
	}
	return previous[len(a)]
}
