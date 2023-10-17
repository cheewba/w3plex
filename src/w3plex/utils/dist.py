class AttrDict(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        super().__getattribute__(name)