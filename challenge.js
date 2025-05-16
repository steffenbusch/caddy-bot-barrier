{{/*
  Converts a hexadecimal string into a Uint8Array.
  This is used to decode the challenge seed and other hex-encoded values.
*/}}
const fromHex = h => new Uint8Array(h.match(/.{1,2}/g).map(b => parseInt(b, 16)));

{{/*
  Converts a Uint8Array into a hexadecimal string.
  This is used to encode the nonce (solution) into a format suitable for cookies.
*/}}
const toHex = b => Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");

const challengeSeed = "{{ .Seed }}";
const challengeMAC = "{{ .MAC }}";
const complexity = {{ .Complexity }};
const seedCookie = "{{ .SeedCookie }}";
const solCookie = "{{ .SolutionCookie }}";
const macCookie = "{{ .MacCookie }}";

{{/*
  The maximum age of the cookies in seconds. This determines how long the cookies
  will remain valid before they expire.
*/}}
const maxAge = {{ .MaxAge }};

{{/*
  Decode the challenge seed from its hex-encoded format into a Uint8Array.
  This will be used as part of the computational challenge.
*/}}
const seed = fromHex(challengeSeed);

{{/*
  Create a buffer to hold both the challenge seed and the nonce (solution).
  The buffer is twice the size of the seed to accommodate both parts.
*/}}
const challengeBuffer = new ArrayBuffer(seed.length * 2);

{{/*
  Create a view into the buffer for the challenge seed.
  This allows us to work with the seed portion of the buffer directly.
*/}}
const challengeSeedView = new Uint8Array(challengeBuffer, 0, seed.length);

{{/*
  Create a view into the buffer for the nonce (solution).
  This allows us to work with the nonce portion of the buffer directly.
*/}}
const challengeNonceView = new Uint8Array(challengeBuffer, seed.length);

{{/*
  Copy the decoded challenge seed into the seed view of the buffer.
*/}}
seed.forEach((v, i) => challengeSeedView[i] = v);

{{/*
  Counts the number of leading zero bits in a given buffer.
  This is used to determine if the hash meets the required complexity.
  The function iterates through each byte and bit in the buffer, counting zero bits
  until the first `1-bit` is encountered. At that point, the count stops because
  any subsequent bits are irrelevant for determining the number of leading zeros.
*/}}
function countLeadingZeros(buf) {
  const view = new Uint8Array(buf);
  let bits = 0;
  for (let byte of view) {
    for (let i = 7; i >= 0; i--) {
      if ((byte >> i) & 1) {
        {{/* Stop counting when the first 1-bit is encountered. */}}
        return bits;
      }
      bits++;
    }
  }
  return bits;
}

{{/*
  Main function to solve the computational challenge.
  This function generates random nonces, computes the hash of the seed and nonce,
  and checks if the hash meets the required complexity.
*/}}
(async () => {
  while (true) {
    {{/*
      Generate a random nonce and store it in the nonce view of the buffer.
      This ensures each attempt uses a different nonce.
    */}}
    crypto.getRandomValues(challengeNonceView);
    {{/*
      Compute the SHA-512 hash of the combined seed and nonce.
    */}}
    const digest = await crypto.subtle.digest("SHA-512", challengeBuffer);
    {{/*
      Count the number of leading zero bits in the hash.
      If the number of leading zero bits meets or exceeds the required complexity,
      the challenge is considered solved.
    */}}
    const leadingZeros = countLeadingZeros(digest);

    if (leadingZeros >= complexity) {
      {{/*
        Computational challenge solved.
        Set the cookies with the challenge seed, solution (nonce), and MAC.
        These cookies will be sent to the server for verification.
      */}}
      document.cookie = `${seedCookie}=${challengeSeed}; Path=/; max-age=${maxAge}; SameSite=Lax; Secure`;
      document.cookie = `${solCookie}=${toHex(challengeNonceView)}; Path=/; max-age=${maxAge}; SameSite=Lax; Secure`;
      document.cookie = `${macCookie}=${challengeMAC}; Path=/; max-age=${maxAge}; SameSite=Lax; Secure`;
      {{/*
        Reload the page to send the cookies to the server and proceed with the request.
      */}}
      window.location.reload();
      return;
    }
  }
})();
