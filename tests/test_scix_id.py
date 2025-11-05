import json
from unittest import TestCase

import SciXPipelineUtils.scix_id as scixid


class TestSciXIDImplementation(TestCase):
    def test_generate_scixid(self):
        test_id = scixid.encode(1000)
        self.assertEqual(test_id, "0000-0000-0Z8A")
        test_int = scixid.decode(test_id)
        self.assertEqual(test_int, 1000)

    def test_generate_scixid_no_checksum(self):
        test_id = scixid.encode(1000, checksum=False)
        self.assertEqual(test_id, "0000-0000-00Z8")
        test_int = scixid.decode(test_id, checksum=False)
        self.assertEqual(test_int, 1000)

    def test_generate_bib_data_hash(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words"],
            "bibcode": "Test",
        }
        hash = scixid.generate_bib_data_hash(test_bib_data)
        self.assertEqual(hash, "703f2f82ef742c10101840e4fc85bc53")

        test_bib_data = {
            "title": "Test",
            "abs": ["words"],
        }
        hash2 = scixid.generate_bib_data_hash(test_bib_data)
        self.assertEqual(hash2, "703f2f82ef742c10101840e4fc85bc53")

        self.assertEqual(hash, hash2)

    def test_get_rand_from_hash(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words"],
        }
        hash = scixid.generate_bib_data_hash(test_bib_data)
        rand_num = scixid.get_rand_from_hash(hash)
        self.assertEqual(rand_num, 8784826954018605)

    def test_scix_id_from_hash(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words"],
        }
        hash = scixid.generate_bib_data_hash(test_bib_data)
        scix_id = scixid.scix_id_from_hash(hash)
        self.assertEqual(scix_id, "7SNR-3N03-VSD6")

    def test_generate_scix_id(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words"],
        }
        scix_id = scixid.generate_scix_id(test_bib_data)
        scix_id_2 = scixid.generate_scix_id(json.dumps(test_bib_data))
        self.assertEqual(scix_id, "9153-JA78-G9SG")
        self.assertEqual(scix_id, scix_id_2)

    def test_generate_scix_id_user_fields(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words"],
        }
        user_fields = ["id"]
        scix_id = scixid.generate_scix_id(test_bib_data, user_fields=user_fields)
        scix_id_2 = scixid.generate_scix_id(test_bib_data)
        self.assertEqual(scix_id, "44GP-FCA0-SEWD")
        self.assertNotEqual(scix_id, scix_id_2)

    def test_generate_scix_id_special_characters_true(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words < <lt\\>"],
        }
        scix_id = scixid.generate_scix_id(test_bib_data)
        scix_id_2 = scixid.generate_scix_id(json.dumps(test_bib_data))
        self.assertEqual(scix_id, "9153-JA78-G9SG")
        self.assertEqual(scix_id, scix_id_2)

    def test_generate_scix_id_special_characters_true_comparison(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words < <lt\\>"],
        }

        test_bib_data_2 = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words <"],
        }

        scix_id = scixid.generate_scix_id(test_bib_data)
        scix_id_2 = scixid.generate_scix_id(test_bib_data_2)
        self.assertEqual(scix_id, "9153-JA78-G9SG")
        self.assertEqual(scix_id, scix_id_2)

    def test_generate_scix_id_special_characters_false(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words < <lt\\>"],
        }
        scix_id = scixid.generate_scix_id(test_bib_data, strip_characters=False)
        scix_id_2 = scixid.generate_scix_id(test_bib_data)
        self.assertEqual(scix_id, "8Z91-4S23-1KJX")
        self.assertNotEqual(scix_id, scix_id_2)

    def test_generate_scix_id_other(self):
        test_bib_data = {
            "id": 1,
            "author": ["Lias, Alberta", "Smith, J."],
            "title": "Test",
            "abs": ["words"],
        }
        scix_id = scixid.generate_scix_id(json.dumps(test_bib_data), hash_data_type="other")
        self.assertNotEqual(scix_id, "9153-JA78-G9SG")
        self.assertEqual(scix_id, "6N22-EN04-7GHF")
