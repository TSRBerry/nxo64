from .range import Range


class Section(object):
    def __init__(self, r, name):
        """
            :type r: Range
            :type name: str
        """
        self.range = r
        self.name = name

    def __repr__(self):
        """
            :return: str
        """
        return 'Section(%r, %r)' % (self.range, self.name)
