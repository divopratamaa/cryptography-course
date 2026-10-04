from collections import Counter  # Counts how often each item occurs, automatically


# ==========================================================
# DECRYPT FUNCTION --> Turns ciphertext back into readable plaintext.
# ==========================================================
def vigenere_decrypt(ciphertext, key):
    # result collects the decrypted text, one character at a time.
    result = ""

    key = key.upper()  # Uppercase the key so the shift calculation is simpler.

    # key_index tracks which letter of the KEY is currently in use.
    # It only advances when a letter is processed.
    key_index = 0

    # Loop over every character in the ciphertext.
    for ch in ciphertext:

        # Only letters are decrypted. (Spaces, digits, punctuation and other
        # characters are left untouched.)
        if ch.isalpha():

            # Turn the KEY letter into a number from 0 to 25:
            # e.g. A -> 0, B -> 1, C -> 2, ..., Z -> 25

            # key_index % len(key) wraps the KEY back to its first letter
            # once its last letter has been used.
            shift = ord(key[key_index % len(key)]) - ord('A')

            # Pick the ASCII starting point depending on the letter's case.
            # 'A'/'B'/... -> use ord('A')
            # 'a'/'b'/... -> use ord('a')
            base = ord('A') if ch.isupper() else ord('a')

            # Vigenere decryption formula: plaintext = ciphertext - shift
            # % 26 keeps the result inside the A-Z range.
            # e.g. C - 2 = A, A - 2 = Y

            # Append the decrypted letter to result.
            result += chr((ord(ch) - base - shift) % 26 + base)

            # Move on to the next KEY letter.
            key_index += 1

        else:
            result += ch  # Non-letters (e.g. spaces) are copied over unchanged.

    return result  # Return the decrypted plaintext.


# ==========================================================
# INDONESIAN LETTER FREQUENCY TABLE
# Most frequent letters: A > N > E > I
# ==========================================================
INDONESIAN_FREQ = {
    'A': 19.81, 'B': 2.97, 'C': 0.67, 'D': 3.72, 'E': 8.18, 'F': 0.25,
    'G': 3.96, 'H': 1.97, 'I': 8.08, 'J': 0.85, 'K': 5.35, 'L': 3.50,
    'M': 4.85, 'N': 9.56, 'O': 1.60, 'P': 2.77, 'Q': 0.00, 'R': 5.00,
    'S': 4.11, 'T': 5.12, 'U': 5.57, 'V': 0.08, 'W': 0.41, 'X': 0.00,
    'Y': 1.60, 'Z': 0.02
}

# The percentage of each letter in Indonesian text.
# Used as the reference point for frequency analysis.


# ==========================================================
# STEPS 1 & 2: FIND REPEATED PATTERNS + MEASURE DISTANCES
# ==========================================================
def kasiski_examination(ciphertext: str, seq_len: int = 3) -> int:
    """
    Kasiski method for estimating the length of a Vigenere key.
    1. Find 3-letter substrings that repeat.
    2. Measure the distance (gap) between their occurrences.
    3. Count how often each factor of those distances appears.
    """

    # Uppercase the ciphertext and drop every non-letter character.
    clean_text = "".join([c for c in ciphertext.upper() if c.isalpha()])

    # Dictionary of patterns and the positions where they occur.
    # e.g. {"ABC": [0, 10, 20]}
    sequences = {}

    # Steps 1 & 2: map positions and distances (gaps)
    # Take every substring of length seq_len.
    for i in range(len(clean_text) - seq_len + 1):

        seq = clean_text[i:i + seq_len]  # Substring of length seq_len.

        if seq not in sequences:
            sequences[seq] = []  # Start a position list for a new pattern.

        sequences[seq].append(i)  # Record where the pattern was found.

    gaps = []  # Every distance between repeated patterns.

    print("Step 1 & 2: Find repeated patterns and measure distances")

    for seq, positions in sequences.items():

        # Only patterns that occur more than once are analysed.
        if len(positions) > 1:

            # Distances between consecutive occurrences.
            # e.g. [5, 15, 25] -> [10, 10]
            seq_gaps = [positions[j] - positions[j - 1] for j in range(1, len(positions))]

            gaps.extend(seq_gaps)  # Add these distances to gaps.

            print(f" - Pattern '{seq}' at indices {positions} -> distances = {seq_gaps}")

    # Without repeated patterns, the KEY length cannot be estimated.
    if not gaps:
        print(" [!] No repetitions found. A longer text is needed.")
        return 0

    # ======================================================
    # STEP 3: COUNT THE FACTORS
    # ======================================================

    factor_counts = Counter()  # How many times each factor appears.

    for gap in gaps:

        # Try factors 2 to 15 as candidate KEY lengths.
        for factor in range(2, 16):

            # If the gap divides evenly by the factor, the factor is a candidate.
            if gap % factor == 0:
                factor_counts[factor] += 1  # One more vote for this factor.

    print("\nStep 3: Count the factors (estimate the key length)")

    # Show the 3 most common factors.
    for factor, count in factor_counts.most_common(3):
        print(f" - Key length {factor}: appears as a factor {count}x")

    # The most common factor is taken as the KEY length.
    predicted_length = factor_counts.most_common(1)[0][0]

    return predicted_length  # Return the KEY length.


# ==========================================================
# STEP 4: FREQUENCY ANALYSIS PER COLUMN -> GUESS THE KEY LETTERS
# ==========================================================
def _chi_squared_score(column_text, shift):
    """Compare a shifted column (Caesar shift) with Indonesian letter frequencies."""

    n = len(column_text)  # Number of letters in the column.

    if n == 0:  # An empty column has nothing to analyse.
        return float('inf')

    # Count the letters after shifting.
    shifted_counts = Counter()

    for ch in column_text:

        # Shift the ciphertext letter back by `shift`.
        original = chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))

        shifted_counts[original] += 1  # Count the shifted letter.

    # Chi-squared score -> the smaller it is, the closer the match to Indonesian.
    score = 0

    # Compare the actual counts with the expected counts.
    for letter, expected_pct in INDONESIAN_FREQ.items():
        # Turn the percentage into an expected number of letters.
        expected_count = expected_pct / 100 * n

        # The actual number of this letter.
        actual_count = shifted_counts.get(letter, 0)

        # Letters with 0% frequency are skipped to avoid dividing by zero.
        if expected_count > 0:
            score += ((actual_count - expected_count) ** 2) / expected_count  # Chi-squared formula.

    return score  # Return the chi-squared score.


def frequency_analysis(ciphertext: str, key_length: int) -> str:
    """
    Step 4: Split the ciphertext into `key_length` columns. Each column is really
    a plain Caesar cipher, so its frequencies reveal one key letter per column.
    Example (key_length=5):
    Column 1 = letters 1, 6, 11, 16...
    Column 2 = letters 2, 7, 12, 17...
    """

    clean_text = "".join([c for c in ciphertext.upper() if c.isalpha()])  # Uppercase, letters only.

    # One column per KEY letter. e.g. key_length = 5 -> ["", "", "", "", ""]
    columns = ["" for _ in range(key_length)]

    # Split the ciphertext into columns.
    for i, ch in enumerate(clean_text):
        columns[i % key_length] += ch  # The column depends on the letter's position.

    print(f"\nStep 4: Frequency analysis per column ({key_length} columns)")

    guessed_key = ""  # The KEY being reconstructed.

    for idx, col in enumerate(columns):  # Analyse each column.
        best_shift, best_score = 0, float('inf')  # Best shift and score so far.

        for shift in range(26):  # Try every shift from A to Z.
            score = _chi_squared_score(col, shift)  # How Indonesian does this shift look?

            if score < best_score:  # Keep the shift with the lowest score.
                best_score = score
                best_shift = shift

        key_letter = chr(best_shift + ord('A'))  # Turn the shift into a KEY letter.

        guessed_key += key_letter  # Add the guessed letter to the KEY.
        print(f" - Column {idx + 1} ({len(col)} letters) -> guessed key letter: '{key_letter}'")

    return guessed_key  # Return the guessed KEY.


# ==========================================================
# CIPHERTEXT -> KEY + PLAINTEXT
# ==========================================================
def crack_vigenere(ciphertext: str):
    print("=== KASISKI METHOD ===")
    print(f"Ciphertext input: {ciphertext}\n")  # Show the ciphertext being analysed.

    # ======================================================
    # STEPS 1-3
    # ======================================================

    # Use Kasiski to estimate the KEY length. seq_len=3 means 3-letter patterns.
    key_length = kasiski_examination(ciphertext, seq_len=3)

    if key_length == 0:  # Stop if the KEY length could not be found.
        print("Could not estimate the key length.")
        return None, None

    print(f"\n[Conclusion, steps 1-3]: Estimated key length is {key_length}")

    # ======================================================
    # STEP 4
    # ======================================================

    guessed_key = frequency_analysis(ciphertext, key_length)  # Guess the KEY with frequency analysis.

    print(f"\n[Conclusion, step 4]: Guessed key is '{guessed_key}'")

    # ======================================================
    # DECRYPTION
    # ======================================================

    decrypted = vigenere_decrypt(ciphertext, guessed_key)  # Decrypt with the guessed KEY.
    print(f"\nDecrypted text: {decrypted}")

    return guessed_key, decrypted  # Return the KEY and the plaintext.


# ==========================================================
# CIPHERTEXT INPUT
# ==========================================================
if __name__ == "__main__":
    # The ciphertext to crack.
    ciphertext = "BEFKWGKVYREQSEPKLYCMYBEFKWGKVYREQSEPKLYCMYBEFKWGKVYREQSEPKLYCMYBEFKWGK"

    guessed_key, recovered_plaintext = crack_vigenere(ciphertext)  # Run the whole attack.

    # ======================================================
    # FINAL RESULT
    # ======================================================
    print("\n" + "=" * 60)
    print("FINAL RESULT")
    print("=" * 60)
    print(f"Key   : {guessed_key}")
    print(f"Plain : {recovered_plaintext}")
