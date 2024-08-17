package canonical

import (
	"bytes"
	"testing"
)

func TestRelaxedHeader(t *testing.T) {
	testCases := []struct {
		header string
		want   string
	}{
		{
			"SubjeCT: Your Name\r\n",
			"subject:Your Name\r\n",
		},
		{
			"Subject \t:\t Your Name\t \r\n",
			"subject:Your Name\r\n",
		},
		{
			"Subject \t:\t Kimi \t \r\n No \t\r\n Na Wa\r\n",
			"subject:Kimi No Na Wa\r\n",
		},
		{
			"Subject \t:\t Ki \tmi \t \r\n No \t\r\n Na Wa\r\n",
			"subject:Ki mi No Na Wa\r\n",
		},
		{
			"Subject \t:\t Ki \tmi \t \r\n No\r\n\t Na Wa\r\n",
			"subject:Ki mi No Na Wa\r\n",
		},
		{
			"Subject: Ki \t mi \t \r\n No\r\n\tNa Wa\r\n",
			"subject:Ki mi No Na Wa\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			got := Header(tc.header, Relaxed)
			if got != tc.want {
				t.Errorf("want %v, but got %v", tc.want, got)
			}
		})
	}

}

func TestSimpleBody(t *testing.T) {
	testCases := []struct {
		body []string
		want string
	}{
		{
			[]string{""},
			"\r\n",
		},
		{
			[]string{"\r\n"},
			"\r\n",
		},
		{
			[]string{"\r\n\r\n\r\n"},
			"\r\n",
		},
		{
			[]string{"Hey\r\n\r\n"},
			"Hey\r\n",
		},
		{
			[]string{"Hey\r\nHow r u?\r\n\r\n\r\n"},
			"Hey\r\nHow r u?\r\n",
		},
		{
			[]string{"Hey\r\n\r\nHow r u?"},
			"Hey\r\n\r\nHow r u?\r\n",
		},
		{
			[]string{"What about\nLF endings?\n\n"},
			"What about\r\nLF endings?\r\n",
		},
		{
			[]string{"\r\n", "\r", "\n"},
			"\r\n",
		},
		{
			[]string{"\r\n", "\r"},
			"\r\n\r\r\n",
		},
		{
			[]string{"\r\n", "\r", "\n", "hey\n", "\n"},
			"\r\n\r\nhey\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			b := bytes.Buffer{}
			wc := SimpleBody(&b)
			for _, body := range tc.body {
				wc.Write([]byte(body))
			}
			wc.Close()
			got := b.String()

			if got != tc.want {
				t.Errorf("want %v, but got %v", tc.want, got)
			}
		})
	}
}

func TestRelaxedBody(t *testing.T) {
	testCases := []struct {
		body string
		want string
	}{
		{
			"",
			"",
		},
		{
			"\r\n",
			"",
		},
		{
			"\r\n\r\n\r\n",
			"",
		},
		{
			"Hey\r\n\r\n",
			"Hey\r\n",
		},
		{
			"Hey\r\nHow r u?\r\n\r\n\r\n",
			"Hey\r\nHow r u?\r\n",
		},
		{
			"Hey\r\n\r\nHow r u?",
			"Hey\r\n\r\nHow r u?\r\n",
		},
		{
			"Hey \t you!",
			"Hey you!\r\n",
		},
		{
			"Hey \t \r\nyou!",
			"Hey\r\nyou!\r\n",
		},
		{
			"Hey\r\n \t you!\r\n",
			"Hey\r\n you!\r\n",
		},
		{
			"Hey\r\n \t \r\n \r\n",
			"Hey\r\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			b := bytes.Buffer{}
			wc := RelaxedBody(&b)
			wc.Write([]byte(tc.body))
			wc.Close()
			got := b.String()

			if got != tc.want {
				t.Errorf("want %v, but got %v", tc.want, got)
			}
		})
	}
}
