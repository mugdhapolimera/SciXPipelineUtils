"""
base32-crockford
================

A Python module implementing the alternate base32 encoding as described
by Douglas Crockford at: http://www.crockford.com/wrmg/base32.html.
Adapted from https://github.com/jbittel/base32-crockford for use in SciX.

He designed the encoding to:

   * Be human and machine readable
   * Be compact
   * Be error resistant
   * Be pronounceable

It uses a symbol set of 10 digits and 22 letters, excluding I, L O and
U. Decoding is not case sensitive, and 'i' and 'l' are converted to '1'
and 'o' is converted to '0'. Encoding uses only upper-case characters.

Hyphens may be present in symbol strings to improve readability, and
are removed when decoding.

A check symbol can be appended to a symbol string to detect errors
within the string.

"""

import hashlib
import json
import random
import re

__all__ = ["encode", "decode", "normalize"]

# The encoded symbol space does not include I, L, O or U
symbols = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# This one symbol is exclusively for checksum values
check_symbols = "U"

encode_symbols = dict((i, ch) for (i, ch) in enumerate(symbols + check_symbols))
decode_symbols = dict((ch, i) for (i, ch) in enumerate(symbols + check_symbols))
normalize_symbols = str.maketrans("IiLlOo", "111100")
valid_symbols = re.compile("^[%s]+[%s]?$" % (symbols, re.escape(check_symbols)))

base = len(symbols)
check_base = len(symbols + check_symbols)


def encode(number, checksum=True, split=4, string_length=12):
    """Encode an integer into a symbol string.

    A ValueError is raised on invalid input.

    If checksum is set to True, a check symbol will be
    calculated and appended to the string.

    If split is specified, the string will be divided into
    clusters of that size separated by hyphens.

    The param string_length causes the returned value to be padded
    with 0s if the returned string is shorter than the requested
    length (ie. 01 becomes 00000001 for the default string length).
    This includes the checksum if specified but not any hyphens from splitting.
    This will also cause a value error to be thrown if encode cannot
    generate a string with the requested length.

    The encoded string is returned.
    """
    number = int(number)
    unencoded_number = number
    if number < 0:
        raise ValueError("number '%d' is not a positive integer" % number)

    split = int(split)
    if split < 0:
        raise ValueError("split '%d' is not a positive integer" % split)

    check_symbol = ""
    if checksum:
        check_symbol = encode_symbols[number % check_base]

    if number == 0:
        symbol_string = "0"

    symbol_string = ""
    while number > 0:
        remainder = number % base
        number //= base
        symbol_string = encode_symbols[remainder] + symbol_string

    symbol_string = str(symbol_string).zfill(string_length - int(checksum))
    if len(symbol_string) != string_length - int(checksum):
        raise ValueError(
            "Failed to generate encode {0} to string with the requested length: {1}. Actual length is {2}".format(
                unencoded_number, string_length - int(checksum), len(symbol_string)
            )
        )
    if split:
        chunks = []
        for pos in range(0, len(symbol_string), split):
            chunks.append(symbol_string[pos : pos + split])
        symbol_string = "-".join(chunks)
        symbol_string = symbol_string + check_symbol

    return symbol_string


def decode(symbol_string, checksum=True, strict=False):
    """Decode an encoded symbol string.

    If checksum is set to True, the string is assumed to have a
    trailing check symbol which will be validated. If the
    checksum validation fails, a ValueError is raised.

    If strict is set to True, a ValueError is raised if the
    normalization step requires changes to the string.

    The decoded string is returned.
    """
    symbol_string = normalize(symbol_string, strict=strict)
    if checksum:
        symbol_string, check_symbol = symbol_string[:-1], symbol_string[-1]

    number = 0
    for symbol in symbol_string:
        number = number * base + decode_symbols[symbol]

    if checksum:
        check_value = decode_symbols[check_symbol]
        modulo = number % check_base
        if check_value != modulo:
            raise ValueError(
                "invalid check symbol '%s' for string '%s'" % (check_symbol, symbol_string)
            )

    return number


def normalize(symbol_string, strict=False):
    """Normalize an encoded symbol string.

    Normalization provides error correction and prepares the
    string for decoding. These transformations are applied:

       1. Hyphens are removed
       2. 'I', 'i', 'L' or 'l' are converted to '1'
       3. 'O' or 'o' are converted to '0'
       4. All characters are converted to uppercase

    A TypeError is raised if an invalid string type is provided.

    A ValueError is raised if the normalized string contains
    invalid characters.

    If the strict parameter is set to True, a ValueError is raised
    if any of the above transformations are applied.

    The normalized string is returned.
    """

    norm_string = symbol_string.replace("-", "").translate(normalize_symbols).upper()

    if not valid_symbols.match(norm_string):
        raise ValueError("string '%s' contains invalid characters" % norm_string)

    if strict and norm_string != symbol_string:
        raise ValueError("string '%s' requires normalization" % symbol_string)

    return norm_string


def get_rand_from_hash(hash, min_val=1, max_val=12800000000000000):
    random.seed(hash)
    return random.randint(min_val, max_val)


def scix_id_from_hash(hash, checksum=True, split=4, string_length=12):
    rand_int = get_rand_from_hash(hash)
    return encode(rand_int)


def _remove_fields_from_hash_data(hash_data, fields_to_remove):
    """Remove specified fields from hash_data dictionary."""
    for field in fields_to_remove:
        try:
            hash_data.pop(field)
        except Exception:
            continue


def _strip_abs_characters(hash_data):
    """Strip HTML and special characters from abstract field."""
    if not hash_data.get("abs"):
        return

    abs_text = hash_data["abs"][0]
    abs_text = re.sub("<[^<]+?>", "", abs_text)
    abs_text = re.sub(r"\W+", "", abs_text)
    abs_text = re.sub(r"&[a-zA-Z]+;", "", abs_text)  # Remove HTML entities
    abs_text = re.sub(r"[^\x00-\x7F]", "", abs_text)  # Remove special Unicode characters
    hash_data["abs"][0] = abs_text


def generate_bib_data_hash(hash_data, strip_characters=True, user_fields=None):
    unique_fields = [
        "id",
        "aff",
        "author",
        "author_count",
        "author_facet",
        "author_norm",
        "author_facet_hier",
        "bibcode",
        "database",
        "first_author",
        "first_author_norm",
        "identifier",
        "orcid_pub",
        "links_data",
        "alternate_bibcode",
        "doctype",
        "doctype_facet_hier",
        "entry_date",
        "keyword_norm",
        "keyword_facet",
        "citation",
        "citation_count",
        "citation_count_norm",
        "read_count",
        "date",
        "copyright",
    ]

    hash_data_fields = list(hash_data.keys())

    if user_fields:
        # If no intersection, treat as if user_fields was None
        if (set(user_fields) & set(hash_data_fields)) == set():
            user_fields = None

    if user_fields:
        fields_to_remove = [f for f in hash_data_fields if f not in user_fields]
        _remove_fields_from_hash_data(hash_data, fields_to_remove)
    else:
        _remove_fields_from_hash_data(hash_data, unique_fields)

    if strip_characters:
        _strip_abs_characters(hash_data)

    encoded_hash_data = json.dumps(hash_data).encode("utf-8")
    return hashlib.md5(encoded_hash_data).hexdigest()


def generate_scix_id(
    hash_data,
    hash_data_type="bib_data",
    checksum=True,
    split=4,
    string_length=12,
    strip_characters=True,
    user_fields=None,
):
    if hash_data_type == "bib_data":
        if type(hash_data) != dict:
            try:
                hash_data = json.loads(hash_data)

            except ValueError as e:
                raise e

        # Use json.dumps with sort_keys=True to sort all nested dictionary keys
        hash_data = json.loads(json.dumps(hash_data, sort_keys=True))
        hashed_data = generate_bib_data_hash(
            hash_data, strip_characters=strip_characters, user_fields=user_fields
        )
    elif hash_data_type == "other":
        encoded_hash_data = str(hash_data).encode("utf-8")
        hashed_data = hashlib.md5(encoded_hash_data).hexdigest()
    else:
        raise ValueError("Invalid hash_data_type")
    return scix_id_from_hash(
        hash=hashed_data, checksum=checksum, split=split, string_length=string_length
    )
