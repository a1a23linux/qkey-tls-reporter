import importlib.util
import pathlib
import tempfile
import unittest

def module(name):
    path = pathlib.Path(__file__).with_name(name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

class ReleaseToolsTest(unittest.TestCase):

    def test_release_checker_rejects_private_material_and_symlinks(self):
        checker = module('check_release')
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            (root / 'README.md').write_text('An example at localhost.\n')
            self.assertEqual(checker.check(root), [])
            (root / 'README.md').write_text('unsafe deployment address: ' + '10.' + '9.1.28\n')
            self.assertTrue(checker.check(root))
            (root / 'README.md').write_text('safe\n')
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                checker.check(root)
if __name__ == '__main__':
    unittest.main()
