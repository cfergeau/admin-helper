package hosts

// ChunkSlices returns new slices with at most 'chunkSize' elements in each.
// It also removes duplicate strings.
func ChunkSlices(chunkSize int, slices ...[]string) [][]string {
	var chunkedSlices [][]string
	var curSlice []string
	uniqueStr := map[string]bool{}

	for _, slice := range slices {
		for _, str := range slice {
			if _, hasStr := uniqueStr[str]; hasStr {
				continue
			}
			curSlice = append(curSlice, str)
			uniqueStr[str] = true
			if len(curSlice) == chunkSize {
				chunkedSlices = append(chunkedSlices, curSlice)
				curSlice = []string{}
			}
		}
	}
	if len(curSlice) != 0 {
		chunkedSlices = append(chunkedSlices, curSlice)
	}

	return chunkedSlices
}
