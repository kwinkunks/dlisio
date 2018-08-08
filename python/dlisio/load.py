from . import core

def load(path):
    return dlis(path)

class dlis(object):

    def __init__(self, path):
        self.fp = core.file(path)
        self.sul = self.fp.sul()

        self.objects = {}
        off = 0
        i = 0
        while not self.fp.eof():
            pos, off, explicit = self.fp.mark(off)

            if explicit:
                self.objects.update(self.elfr(pos))
                i += 1
            else:
                print('IFLR')
                break

            if i > 2: break

        print(self.objects)

    def elfr(self, pos):
        s = self.fp.elfr(pos)

        objects = s['objects']

        return {
            name: {
                o['label']: {
                    k: o[k] for k in ['units', 'value'] if k in o
                } for o in structure
            } for name, structure in objects.items()
        }

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fp.close()

    @property
    def label(self):
        return self.sul
