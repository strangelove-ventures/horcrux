package keygen

// LocalDKG simulates a DKG key combination ceremony. TEST USE ONLY.
func LocalDKG(threshold, total uint8) (map[uint8]Cosigner, error) {
	cosigners := make(map[uint8]Cosigner)

	var err error
	for i := uint8(1); i <= total; i++ {
		cosigners[i], err = NewCosigner(i, threshold, total)
		if err != nil {
			return nil, err
		}
	}

	msgsOut1 := make([][]byte, 0, total)

	for _, c := range cosigners {
		msgs1, err := c.Round1()
		if err != nil {
			return nil, err
		}

		msgsOut1 = append(msgsOut1, msgs1...)
	}

	msgsOut2 := make([][]byte, 0, total*(total-1)/2)

	for _, c := range cosigners {
		msgs2, err := c.Round2(msgsOut1)
		if err != nil {
			return nil, err
		}

		msgsOut2 = append(msgsOut2, msgs2...)
	}

	for _, c := range cosigners {
		if err := c.Round3(msgsOut2); err != nil {
			return nil, err
		}
		if err := c.WaitForCompletion(); err != nil {
			return nil, err
		}
	}

	return cosigners, nil
}
