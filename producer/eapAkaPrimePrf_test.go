package producer

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEAPAKAPrimePrf(t *testing.T) {
	testCases := []struct {
		identity string
		ikPrime  string
		ckPrime  string
		K_encr   string
		K_aut    string
		K_re     string
		MSK      string
		EMSK     string
	}{
		{
			"0555444333222111",
			"ccfc230ca74fcc96c0a5d61164f5a76c",
			"0093962d0dd84aa5684b045c9edffa04",
			"766fa0a6c317174b812d52fbcd11a179",
			"0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea",
			"cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a",
			"67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a",
			"f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb",
		},
		{
			"0555444333222111",
			"db94a0ab557ef6c9ab48619ca05b9a9f",
			"3820f0277fa5f77732b1fb1d90c1a0da",
			"05ad73ac915fce89ac77e1520d82187b",
			"5b4acaef62c6ebb8882b2f3d534c4b35277337a00184f20ff25d224c04be2afd",
			"3f90bf5c6e5ef325ff04eb5ef6539fa8cca8398194fbd00be425b3f40dba10ac",
			"87b321570117cd6c95ab6c436fb5073ff15cf85505d2bc5bb7355fc21ea8a75757e8f86a2b138002e05752913bb43b82f868a96117e91a2d95f526677d572900",
			"c891d5f20f148a1007553e2dea555c9cb672e9675f4a66b4bafa027379f93aee539a5979d0a0042b9d2ae28bed3b17a31dc8ab75072b80bd0c1da612466e402c",
		},
		{
			"0555444333222111",
			"3ece6b705dbbf7dfc459a11280c65524",
			"cd4c8e5c68f57dd1d7d7dfd0c538e577",
			"897d302fa2847416488c28e20dcb7be4",
			"c40700e7722483ae3dc7139eb0b88bb558cb3081eccd057f9207d1286ee7dd53",
			"0a591a22dd8b5b1cf29e3d508c91dbbdb4aee23051892c42b6a2de66ea504473",
			"9f7dca9e37bb22029ed986e7cd09d4a70d1ac76d95535c5cac40a7504699bb8961a29ef6f3e90f183de5861ad1bedc81ce9916391b401aa006c98785a5756df7",
			"724de00bdb9e568187be3fe746114557d5018779537ee37f4d3c6c738cb97b9dc651bc19bfadc344ffe2b52ca78bd8316b51dacc5f2b1440cb9515521cc7ba23",
		},
		{
			"0555444333222111",
			"3ece6b705dbbf7dfc459a11280c65524",
			"cd4c8e5c68f57dd1d7d7dfd0c538e577",
			"897d302fa2847416488c28e20dcb7be4",
			"c40700e7722483ae3dc7139eb0b88bb558cb3081eccd057f9207d1286ee7dd53",
			"0a591a22dd8b5b1cf29e3d508c91dbbdb4aee23051892c42b6a2de66ea504473",
			"9f7dca9e37bb22029ed986e7cd09d4a70d1ac76d95535c5cac40a7504699bb8961a29ef6f3e90f183de5861ad1bedc81ce9916391b401aa006c98785a5756df7",
			"724de00bdb9e568187be3fe746114557d5018779537ee37f4d3c6c738cb97b9dc651bc19bfadc344ffe2b52ca78bd8316b51dacc5f2b1440cb9515521cc7ba23",
		},
	}
	for _, testData := range testCases {
		K_encr, K_aut, K_re, MSK, EMSK := eapAkaPrimePrf(testData.ikPrime, testData.ckPrime, testData.identity)
		assert.True(t, testData.K_encr == K_encr)
		assert.True(t, testData.K_aut == K_aut)
		assert.True(t, testData.K_re == K_re)
		assert.True(t, testData.MSK == MSK)
		assert.True(t, testData.EMSK == EMSK)
	}
}
